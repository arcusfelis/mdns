%% @author Uvarov Michael <arcusfelis@gmail.com>
%% @doc
%% Large packets are splited into chunks.
%%
%% Peer sends advertisment with TTL=0 before exiting.
%% Example of this from annlist:
%%
%% ```
%% #dns_rr{domain = "4d336d342d312d2d343834616435313564343437._bittorrent._tcp.local",
%%      type = srv,class = 32769,cnt = 0,ttl = 0,
%%      data = {0,0,555,"omicron.local"},
%%      tm = undefined,bm = [],func = false}
%% '''
%%
%% @end
-module(mdns_net).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("kernel/src/inet_dns.hrl").

-behaviour(gen_server).
-compile({parse_transform, lager_transform}).


% Public interface
-export([start_link/3,
         publish_service/3,
         publish_service/4]).

% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
    socket :: inet:socket(),
    host_name :: string(),
    domain :: string(),
    broadcast_ip,
    broadcast_port
}).

%
% Type definitions and function specifications
%


%
% Contacts and settings
%
srv_name() ->
   mdns_socket_server.

socket_options(ListenIP, IFace) ->
    If = case IFace of
             undefined -> multicast_if();
             _ -> IFace
         end,
    lager:info("Multicast interface is ~p.", [If]),
    [{reuseaddr, true},
     {multicast_if, If},
     {broadcast, true},
     {active, true}, {mode, binary}]
    ++ case ListenIP of all -> []; ListenIP -> [{ip, ListenIP}] end.

%
% Public interface
%
start_link(ListenIP, ListenPort, ExternalIP) ->
    Args = [ListenIP, ListenPort, ExternalIP],
    gen_server:start_link({local, srv_name()}, ?MODULE, Args, []).


%% @doc Publish a service.
%% `avahi-publish-service 4d336d342d312d2d343834616435313564343437 _bittorrent._tcp 555'
%e will be `publish_service("4d336d342d312d2d343834616435313564343437", "_bittorrent._tcp", 555)'.
publish_service(Name, ServiceType, Port) ->
    publish_service(Name, ServiceType, Port, []).

publish_service(Name, ServiceType, Port, SubServices) ->
    gen_server:call(srv_name(), {publish_service, Name, ServiceType, Port, SubServices}).
    

%% ==================================================================

init([ListenIP, ListenPort, IFace]) ->
    {ok, Socket} = gen_udp:open(ListenPort,
                                socket_options(ListenIP, IFace)),
    %% TODO: We want "omicron.local", this call returns "omicron.lan".
    HostName = net_adm:localhost(),
    State = #state{socket=Socket,
                   domain="local",
                   host_name=HostName,
                   broadcast_ip=ListenIP,
                   broadcast_port=ListenPort},
    {ok, State}.

handle_call({publish_service, Name, ServiceType, Port, SubServices}, _From,
            State=#state{socket=Socket, host_name=HostName, domain=Domain,
                         broadcast_ip=BIP, broadcast_port=BPort}) ->
    SrvDomain = service_srv_domain(Name, ServiceType, Domain),
    PtrDomain = service_ptr_domain(ServiceType, Domain),
    Rec = #dns_rec{
        header = query_packet_header(),
        anlist =  [service_ptr_dns_rr(sub_service_ptr_domain(SubServiceName, ServiceType, Domain), SrvDomain)
                   || SubServiceName <- SubServices] ++
                  [service_ptr_dns_rr(PtrDomain, SrvDomain),
                   services_in_dns_rr(Domain, PtrDomain),
                   service_srv_dns_rr(SrvDomain, HostName, Port)]},
    gen_udp:send(Socket, BIP, BPort, inet_dns:encode(Rec)),
    {reply, ok, State}.


handle_cast(not_implemented, State) ->
    {noreply, State}.


handle_info({udp, _Socket, IP, Port, Packet},
            #state{} = State) ->
    lager:debug("Receiving a packet from ~p:~p of size ~B~n",
                [IP, Port, byte_size(Packet)]),
    case inet_dns:decode(Packet) of
        {ok, Rec} ->
            lager:debug("Decoded ~s~n", [pretty(Rec)]),
            inspect_packet(Rec, IP),
            {noreply, State};
        {error, Reason} ->
            lager:debug("Decoding failed with reason ~p", [Reason]),
            {noreply, State}
    end;

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_, _State) ->
    ok.

code_change(_, _, State) ->
    {ok, State}.

%% ==================================================================

%% ======================================================================
%% Helpers for debugging.

pretty(Term) ->
    io_lib_pretty:print(Term, fun record_definition/2).

record_definition(Name, FieldCount) ->
%   io:format(user, "record_definition(~p, ~p)~n", [Name, FieldCount]),
%   io:format(user, "record_definition_list() = ~p~n", [record_definition_list()]),
    record_definition_1(Name, FieldCount+1, record_definition_list()).

record_definition_1(Name, Size, [{Name, Size, Fields}|_]) ->
    Fields;
record_definition_1(Name, Size, [{_, _, _}|T]) ->
    record_definition_1(Name, Size, T);
record_definition_1(_Name, _Size, []) ->
    no.


-define(REC_DEF(Name),
        {Name, record_info(size, Name), record_info(fields, Name)}).

record_definition_list() ->
    [?REC_DEF(state)
    ,?REC_DEF(dns_rec)
    ,?REC_DEF(dns_header)
    ,?REC_DEF(dns_rr)
    ].


%% ======================================================================
%% Detect interface for multicast.

multicast_if() ->
    {ok, Interfaces} = inet:getifaddrs(),
    multicast_if(Interfaces).

multicast_if([{_, H} | T]) ->
    case is_running_multicast_interface(proplists:get_value(flags, H)) andalso proplists:is_defined(addr, H) of
        true ->
            v4(proplists:get_all_values(addr, H));
        false ->
            multicast_if(T)
    end.

v4([{_, _, _, _} = V4 | _]) ->
    V4;
v4([_ | T]) ->
    v4(T).

is_running_multicast_interface(Flags) ->
    lists:member(up, Flags) andalso
        lists:member(broadcast, Flags) andalso
        lists:member(running, Flags) andalso
        lists:member(multicast, Flags).


%% ======================================================================
%% MDNS

query_packet_header() ->
    #dns_header{
        id = 0,
        qr = true,
        opcode = 'query',
        aa = true,
        tc = false,
        rd = false,
        ra = false,
        pr = false,
        rcode = 0}.


%% #dns_rr{
%% domain = "4d336d342d312d2d343834616435313564343437._bittorrent._tcp.local",
%% type = srv,class = 32769,cnt = 0,ttl = 120,
%% data = {0,0,555,"omicron.local"},
%% tm = undefined,bm = [],func = false}
service_srv_dns_rr(SrvDomain, HostName, Port) ->
    #dns_rr{
        domain = SrvDomain,
        type = srv,
        class = 32769,
        cnt = 0,
        ttl = 120,
        data = {0,0,Port,HostName},
        tm = undefined,
        bm = [],
        func = false}.

%% #dns_rr{domain = "_bittorrent._tcp.local",type = ptr,
%% class = in,cnt = 0,ttl = 4500,
%% data = "4d336d342d312d2d343834616435313564343437._bittorrent._tcp.local",
%% tm = undefined,bm = [],func = false},
service_ptr_dns_rr(PtrDomain, SrvDomain) ->
    #dns_rr{
        domain = PtrDomain,
        type = ptr,
        class = in,
        cnt = 0,
        ttl = 4500,
        data = SrvDomain,
        tm = undefined,
        bm = [],
        func = false}.

%% #dns_rr{domain = "_services._dns-sd._udp.local",type = ptr,
%% class = in,cnt = 0,ttl = 4500,
%% data = "_bittorrent._tcp.local",tm = undefined,
%% bm = [],func = false}.
services_in_dns_rr(Domain, PtrDomain) ->
    #dns_rr{
        domain = "_services._dns-sd._udp." ++ Domain,
        type = ptr,
        class = in,
        cnt = 0,
        ttl = 4500,
        data = PtrDomain,
        tm = undefined,
        bm = [],
        func = false}.


service_srv_domain(Name, ServiceType, Domain) ->
    Name ++ "." ++ ServiceType ++ "." ++ Domain.

sub_service_ptr_domain(SubServiceName, ServiceType, Domain) ->
    SubServiceName ++ "._sub." ++ ServiceType ++ "." ++ Domain.

service_ptr_domain(ServiceType, Domain) ->
    ServiceType ++ "." ++ Domain.

service_ptr_domain_to_type(PtrDomain, Domain) ->
    lists2:delete_suffix("." ++ Domain, PtrDomain).

service_srv_domain_to_name(SrvDomain, PtrDomain) ->
    lists2:delete_suffix("." ++ PtrDomain, SrvDomain).


inspect_packet(#dns_rec{ anlist = RRs }, IP) ->
    [begin
        %% PtrDomain = "_bittorrent._tcp.local"
        %% ServiceType = "_bittorrent._tcp"
        ServiceType = service_ptr_domain_to_type(PtrDomain, Domain),
        %% SrvDomain = "4d336d342d312d2d343834616435313564343437._bittorrent._tcp.local"
        {ok, #dns_rr{type = ptr, class = in, data = SrvDomain}} =
            follow_pointer(PtrDomain, RRs),
        {SrvTTL, ServicePort} =
        case follow_pointer(SrvDomain, RRs) of
        {ok, #dns_rr{
            type = ptr, class = srv,
            data = {0,0,Port1,_HostName},
            ttl = SrvTTL1}} ->
            {SrvTTL1, Port1};
        _ ->
            {undefined, undefined}
        end,
        ServiceName = service_srv_domain_to_name(SrvDomain, PtrDomain),
        SubServiceSuffix = "._sub." ++ ServiceType ++ "." ++ Domain,
        SubServices = extract_subservices(SrvDomain, SubServiceSuffix, RRs),
        [mdns_event:notify_sub_service_down(ServiceName, ServiceType, IP, SubType)
        || {SubType, 0} <- SubServices],
        [mdns_event:notify_sub_service_up(ServiceName, ServiceType, IP, SubType)
        || {SubType, TTL} <- SubServices, TTL > 0],
        case SrvTTL of
        undefined ->
            ok;
        0 ->
            mdns_event:notify_service_up(ServiceName, ServiceType, IP, ServicePort);
        _ ->
            mdns_event:notify_service_down(ServiceName, ServiceType, IP, ServicePort)
        end,
        ok
     end
     || #dns_rr{domain = "_services._dns-sd._udp." ++ Domain,
                type = ptr, class = in, data = PtrDomain} <- RRs].

-spec follow_pointer(string(), list(#dns_rr{})) -> {ok, #dns_rr{}} | {error, not_found}.
follow_pointer(PtrDomain, [RR=#dns_rr{domain = PtrDomain} | _]) ->
    {ok, RR};
follow_pointer(PtrDomain, [_ | RRs]) ->
    follow_pointer(PtrDomain, RRs);
follow_pointer(_, []) ->
    {error, not_found}.
    
extract_subservices(SrvDomain, SubServiceSuffix, 
    [#dns_rr{type = ptr, class=in, data = SrvDomain, domain = SSDomain, ttl=TTL}|RRs]) ->
    case lists:suffix(SubServiceSuffix, SSDomain) of
        true ->
            [{lists2:delete_suffix(SubServiceSuffix, SSDomain), TTL}
            |extract_subservices(SrvDomain, SubServiceSuffix, RRs)];
        false ->
            extract_subservices(SrvDomain, SubServiceSuffix, RRs)
    end;
extract_subservices(SrvDomain, SubServiceSuffix, [_|RRs]) ->
    extract_subservices(SrvDomain, SubServiceSuffix, RRs);
extract_subservices(_, _, []) ->
    [].
        
    


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
         publish_service/4,
         unpublish_service/3,
         unpublish_service/4]).

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


unpublish_service(Name, ServiceType, Port) ->
    unpublish_service(Name, ServiceType, Port, []).

unpublish_service(Name, ServiceType, Port, SubServices) ->
    gen_server:call(srv_name(), {unpublish_service, Name, ServiceType, Port, SubServices}).
    

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
    ReqRec = #dns_rec{
        header = query_packet_header(),
        qdlist = [service_in_dns_query(SrvDomain)],
        nslist = [service_srv_in_dns_rr(SrvDomain, HostName, Port, true)]},
    ResRec = #dns_rec{
        header = query_packet_header(),
        anlist =  [service_ptr_dns_rr(
                      sub_service_ptr_domain(SubServiceName, ServiceType, Domain),
                      SrvDomain, true)
                   || SubServiceName <- SubServices] ++
                  [service_ptr_dns_rr(PtrDomain, SrvDomain, true),
                   services_in_dns_rr(Domain, PtrDomain, true),
                   service_srv_dns_rr(SrvDomain, HostName, Port, true)]},
    gen_udp:send(Socket, BIP, BPort, inet_dns:encode(ReqRec)),
    gen_udp:send(Socket, BIP, BPort, inet_dns:encode(ResRec)),
    {reply, ok, State};

handle_call({unpublish_service, Name, ServiceType, Port, SubServices}, _From,
            State=#state{socket=Socket, host_name=HostName, domain=Domain,
                         broadcast_ip=BIP, broadcast_port=BPort}) ->
    SrvDomain = service_srv_domain(Name, ServiceType, Domain),
    PtrDomain = service_ptr_domain(ServiceType, Domain),
    ResRec = #dns_rec{
        header = query_packet_header(),
        anlist =  [service_ptr_dns_rr(
                      sub_service_ptr_domain(SubServiceName, ServiceType, Domain),
                      SrvDomain, false)
                   || SubServiceName <- SubServices] ++
                  [service_ptr_dns_rr(PtrDomain, SrvDomain, false),
                   services_in_dns_rr(Domain, PtrDomain, false),
                   service_srv_dns_rr(SrvDomain, HostName, Port, false)]},
    gen_udp:send(Socket, BIP, BPort, inet_dns:encode(ResRec)),
    {reply, ok, State}.


handle_cast(not_implemented, State) ->
    {noreply, State}.


handle_info({udp, _Socket, IP, Port, Packet},
            #state{domain=Domain} = State) ->
    lager:debug("Receiving a packet from ~p:~p of size ~B~n",
                [IP, Port, byte_size(Packet)]),
    case inet_dns:decode(Packet) of
        {ok, Rec} ->
            lager:debug("Decoded ~s~n", [pretty(Rec)]),
            inspect_respond_packet(Rec, IP, Domain),
            inspect_request_packet(Rec, IP, Domain),
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
    ,?REC_DEF(dns_query)
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
service_srv_dns_rr(SrvDomain, HostName, Port, IsEnable) ->
    #dns_rr{
        domain = SrvDomain,
        type = srv,
        class = 32769,
        cnt = 0,
        ttl = case IsEnable of true -> 120; false -> 0 end,
        data = {0,0,Port,HostName},
        tm = undefined,
        bm = [],
        func = false}.

service_srv_in_dns_rr(SrvDomain, HostName, Port, IsEnable) ->
    #dns_rr{
        domain = SrvDomain,
        type = srv,
        class = in,
        cnt = 0,
        ttl = case IsEnable of true -> 120; false -> 0 end,
        data = {0,0,Port,HostName},
        tm = undefined,
        bm = [],
        func = false}.

%% #dns_rr{domain = "_bittorrent._tcp.local",type = ptr,
%% class = in,cnt = 0,ttl = 4500,
%% data = "4d336d342d312d2d343834616435313564343437._bittorrent._tcp.local",
%% tm = undefined,bm = [],func = false},
service_ptr_dns_rr(PtrDomain, SrvDomain, IsEnable) ->
    #dns_rr{
        domain = PtrDomain,
        type = ptr,
        class = in,
        cnt = 0,
        ttl = case IsEnable of true -> 4500; false -> 0 end,
        data = SrvDomain,
        tm = undefined,
        bm = [],
        func = false}.

%% #dns_rr{domain = "_services._dns-sd._udp.local",type = ptr,
%% class = in,cnt = 0,ttl = 4500,
%% data = "_bittorrent._tcp.local",tm = undefined,
%% bm = [],func = false}.
services_in_dns_rr(Domain, PtrDomain, IsEnable) ->
    #dns_rr{
        domain = "_services._dns-sd._udp." ++ Domain,
        type = ptr,
        class = in,
        cnt = 0,
        ttl = case IsEnable of true -> 4500; false -> 0 end,
        data = PtrDomain,
        tm = undefined,
        bm = [],
        func = false}.


service_in_dns_query(SrvDomain) ->
    #dns_query{domain = SrvDomain, type = any, class = in}.


service_srv_domain(Name, ServiceType, Domain) ->
    escape_name(Name) ++ "." ++ ServiceType ++ "." ++ Domain.

sub_service_ptr_domain(SubServiceName, ServiceType, Domain) ->
    SubServiceName ++ "._sub." ++ ServiceType ++ "." ++ Domain.

service_ptr_domain(ServiceType, Domain) ->
    ServiceType ++ "." ++ Domain.

service_ptr_domain_to_type(PtrDomain, Domain) ->
    lists2:delete_suffix("." ++ Domain, PtrDomain).

service_srv_domain_to_name(SrvDomain, PtrDomain) ->
    lists2:delete_suffix("." ++ PtrDomain, SrvDomain).


%% anlist: list of answer entries
%% nslist: list of authority entries
%% qdlist: list of question entries
inspect_respond_packet(#dns_rec{ anlist = RRs }, IP, Domain) ->
    [begin
        %% PtrDomain = "_bittorrent._tcp.local"
        %% ServiceType = "_bittorrent._tcp"
        ServiceType = service_ptr_domain_to_type(PtrDomain, Domain),
        %% SrvDomain = "4d336d342d312d2d343834616435313564343437._bittorrent._tcp.local"
        {ok, #dns_rr{type = ptr, class = in, data = SrvDomain}} =
            follow_pointer(PtrDomain, ptr, RRs),
        {SrvTTL, ServicePort} =
        case follow_pointer(SrvDomain, srv, RRs) of
        {ok, #dns_rr{
            type = srv, % class = 32769,
            data = {0,0,Port1,_HostName},
            ttl = SrvTTL1}} ->
            {SrvTTL1, Port1};
        {ok, RR} ->
            lager:debug("Bad record ~p.", [RR]),
            {undefined, undefined};
        {error, Reason} ->
            lager:debug("Domain ~p not found.", [SrvDomain]),
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
            lager:debug("Ignore service."),
            ok;
        0 ->
            mdns_event:notify_service_down(ServiceName, ServiceType, IP, ServicePort);
        _ ->
            mdns_event:notify_service_up(ServiceName, ServiceType, IP, ServicePort)
        end,
        ok
     end
     || #dns_rr{domain = "_services._dns-sd._udp." ++ Domain1,
                type = ptr, class = in, data = PtrDomain} <- RRs,
        Domain =:= Domain1].

inspect_request_packet(#dns_rec{qdlist=Qs}, IP, Domain) ->
    %% SrvDomain = "4d336d342d312d2d343834616435313564343437._bittorrent._tcp.local"
    %% ServiceName = "4d336d342d312d2d343834616435313564343437"
    %% PtrDomain = "_bittorrent._tcp.local"
    [begin
        {ServiceName, PtrDomain} = split_name(SrvDomain),
        ServiceType = service_ptr_domain_to_type(PtrDomain, Domain),
        mdns_event:notify_service_request(ServiceType, IP)
     end
    || #dns_query{domain = SrvDomain} <- Qs].

-spec follow_pointer(string(), atom(), list(#dns_rr{})) -> {ok, #dns_rr{}} | {error, not_found}.
follow_pointer(Domain, Type, [RR=#dns_rr{type = Type, domain = Domain} | _]) ->
    {ok, RR};
follow_pointer(Domain, Type, [_ | RRs]) ->
    follow_pointer(Domain, Type, RRs);
follow_pointer(_, _, []) ->
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
        
    
split_name(Domain) ->
    split_name_1(Domain, "").

split_name_1("\\." ++ Domain, Acc) ->
    split_name_1(Domain, [$. | Acc]);
split_name_1("\\\\" ++ Domain, Acc) ->
    split_name_1(Domain, [$. | Acc]);
split_name_1("." ++ Domain, Acc) ->
    {lists:reverse(Acc), Domain};
split_name_1([H|Domain], Acc) ->
    split_name_1(Domain, [H | Acc]).
    

escape_name("." ++ Name) ->
    "\\." ++ escape_name(Name);
escape_name("\\" ++ Name) ->
    "\\\\" ++ escape_name(Name);
escape_name([H|Name]) ->
    [H] ++ escape_name(Name);
escape_name("") ->
    "".
    

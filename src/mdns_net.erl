%% @author Uvarov Michael <arcusfelis@gmail.com>
%% @doc TODO
%% @end
-module(mdns_net).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("kernel/src/inet_dns.hrl").

-behaviour(gen_server).
-compile({parse_transform, lager_transform}).


% Public interface
-export([start_link/3]).

% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
    socket :: inet:socket()
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
     {active, true}, {mode, binary}]
    ++ case ListenIP of all -> []; ListenIP -> [{ip, ListenIP}] end.

%
% Public interface
%
start_link(ListenIP, ListenPort, ExternalIP) ->
    Args = [ListenIP, ListenPort, ExternalIP],
    gen_server:start_link({local, srv_name()}, ?MODULE, Args, []).
    

%% ==================================================================

init([ListenIP, ListenPort, IFace]) ->
    {ok, Socket} = gen_udp:open(ListenPort,
                                socket_options(ListenIP, IFace)),
    State = #state{socket=Socket},
    {ok, State}.

handle_call(x, _From, State) ->
    {reply, ok, State}.


handle_cast(not_implemented, State) ->
    {noreply, State}.


handle_info({udp, _Socket, IP, Port, Packet},
            #state{} = State) ->
    lager:debug("Receiving a packet from ~p:~p~n", [IP, Port]),
    lager:debug("Data ~p~n", [Packet]),
    {noreply, State};

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



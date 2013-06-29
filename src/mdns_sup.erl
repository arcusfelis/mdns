-module(mdns_sup).
-behaviour(supervisor).

%% API
-export([start_link/0,
         start_link/4]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).
-define(APP, mdns).

%% ====================================================================

%% @doc Start the supervisor
%% @end
-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    ListenPort = get_app_env(listen_port, 5353),
    IFace      = get_app_env(interface),
    ListenIP   = get_app_env(listen_ip, {224,0,0,251}),
    Domain     = get_app_env(domain, "local"),
    start_link(ListenIP, ListenPort, IFace, Domain).

start_link(ListenIP, ListenPort, IFace, Domain) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE,
                          [ListenIP, ListenPort, IFace, Domain]).


%% ====================================================================

%% @private
init([ListenIP, ListenPort, IFace, Domain]) ->
    Net = {mdns_net,
           {mdns_net, start_link, [ListenIP, ListenPort, IFace, Domain]},
            permanent, 5000, worker, [mdns_net]},

    Event = {mdns_event,
           {mdns_event, start_link, []},
            permanent, 5000, worker, [mdns_event]},

    {ok, {{one_for_all, 3, 60}, [Event, Net]}}.


%% ====================================================================
get_app_env(Key) ->
    get_app_env(Key, undefined).

get_app_env(Key, Def) ->
    case application:get_env(?APP, Key) of
        {ok, Value} -> Value;
        undefined -> Def
    end.

get_required_app_env(Key) ->
    case application:get_env(?APP, Key) of
        {ok, Value} -> Value;
        undefined -> erlang:error({undefined_env_var, Key})
    end.


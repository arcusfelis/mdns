-module(mdns_sup).
-behaviour(supervisor).

%% API
-export([start_link/0,
         start_link/3]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).
-define(APP, mdns).

%% ====================================================================

%% @doc Start the supervisor
%% @end
-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    ListenPort = get_required_app_env(listen_port),
    IFace      = get_app_env(interface),
    ListenIP   = get_app_env(listen_ip, all),
    start_link(ListenIP, ListenPort, IFace).

start_link(ListenIP, ListenPort, IFace) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE,
                          [ListenIP, ListenPort, IFace]).


%% ====================================================================

%% @private
init([ListenIP, ListenPort, IFace]) ->
    Net = {mdns_net,
           {mdns_net, start_link, [ListenIP, ListenPort, IFace]},
            permanent, 5000, worker, [mdns_net]},

    {ok, {{one_for_all, 3, 60}, [Net]}}.


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


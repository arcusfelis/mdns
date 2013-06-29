-module(mdns_console_h).
-behaviour(gen_event).

-export([init/1,
	 terminate/2,
	 handle_info/2,
	 handle_call/2,
	 handle_event/2,
     code_change/3]).

init(_) ->
    {ok, stateless}.

terminate(remove_handler, _) ->
    ok;
terminate(stop, _) ->
    ok;
terminate(Error, State) ->
    error_logger:error_report([{module, ?MODULE},
			       {self, self()},
			       {error, Error},
			       {state, State}]).

handle_event(Event, State) ->
    lager:debug("Event ~p", [Event]),
    {ok, State}.

handle_info({'EXIT', _, shutdown}, _) ->
    remove_handler.

handle_call(_, _) ->
    error(badarg).

code_change(_, _, State) ->
    {ok, State}.

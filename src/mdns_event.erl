-module(mdns_event).
-export([
    start_link/0,
    add_handler/1,
    add_sup_handler/1,
    add_sup_handler/2,
	add_handler/2,
	mgr_name/0,
	notify_service_up/4,
    notify_service_down/4,
    notify_sub_service_up/4,
    notify_sub_service_down/4,
    notify_service_request/2]).

start_link() ->
    {ok, Pid} = gen_event:start_link({local, mgr_name()}),
    add_handler(mdns_console_h),
    {ok, Pid}.

mgr_name() ->
    mdns_node_discovery_mgr_name.

add_sup_handler(Handler) ->
    add_sup_handler(Handler, []).

add_sup_handler(Handler, Args) ->
    gen_event:add_sup_handler(mgr_name(), Handler, Args).

add_handler(Handler) ->
    add_handler(Handler, []).

add_handler(Handler, Args) ->
    gen_event:add_handler(mgr_name(), Handler, Args).

notify_service_up(Name, ServiceType, IP, ServicePort) ->
    notify(mgr_name(), {service_up, Name, ServiceType, IP, ServicePort}).

notify_service_down(Name, ServiceType, IP, ServicePort) ->
    notify(mgr_name(), {service_down, Name, ServiceType, IP, ServicePort}).

notify_sub_service_up(Name, ServiceType, IP, SubType) ->
    notify(mgr_name(), {sub_service_up, Name, ServiceType, IP, SubType}).

notify_sub_service_down(Name, ServiceType, IP, SubType) ->
    notify(mgr_name(), {sub_service_down, Name, ServiceType, IP, SubType}).


notify_service_request(ServiceType, IP) ->
    notify(mgr_name(), {service_request, ServiceType, IP}).

notify(Manager, Message) ->
    gen_event:notify(Manager, Message).


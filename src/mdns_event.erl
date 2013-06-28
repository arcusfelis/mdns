-module(mdns_event).
-export([
    start_link/0,
    add_handler/1,
	add_handler/2,
	mgr_name/0,
	notify_service_up/4,
    notify_service_down/4,
    notify_sub_service_up/4,
    notify_sub_service_down/4]).

start_link() ->
    gen_event:start_link({local, mgr_name()}).

mgr_name() ->
    mdns_node_discovery_mgr_name.

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
    notify(mgr_name(), {sub_service_up, Name, ServiceType, IP, SubType}).

notify(Manager, Message) ->
    gen_event:notify(Manager, Message).


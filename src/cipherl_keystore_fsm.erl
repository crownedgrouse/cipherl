-module(cipherl_keystore_fsm).
-behaviour(gen_statem).

%% API.
-export([start_link/0]).

%% gen_statem.
-export([callback_mode/0]).
-export([init/1]).

-export([monitor_nodes/3]).

-export([handle_event/4]).
-export([terminate/3]).
-export([code_change/4]).

-record(state, {
}).

%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
	gen_statem:start_link(?MODULE, [], []).

%% gen_statem.

callback_mode() ->
	state_functions.

init([]) ->
    logger:info("Starting ~p", [?MODULE]),
	{ok, monitor_nodes, #state{}}.

monitor_nodes({call, {From, Tag}}, EventData, StateData) when is_pid(From)->
    logger:info("~p~p call received from ~p: ~p", [?MODULE, self(), {From, Tag}, EventData]),
	{next_state, monitor_nodes, StateData};
monitor_nodes(cast, EventData, StateData) ->
    logger:info("~p~p cast received: ~p", [?MODULE, self(), EventData]),
    {next_state, monitor_nodes, StateData};
monitor_nodes(info, EventData, StateData) ->
    logger:info("~p~p info received: ~p", [?MODULE, self(), EventData]),
    {next_state, monitor_nodes, StateData}.

handle_event(_EventType, _EventData, StateName, StateData) ->
	{next_state, StateName, StateData}.

terminate(_Reason, _StateName, _StateData) ->
	ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
	{ok, StateName, StateData}.

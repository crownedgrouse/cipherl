-module(cipherl_algos_fsm).
-behaviour(gen_statem).

%% API.
-export([start_link/0]).

%% gen_statem.
-export([callback_mode/0]).
-export([init/1]).
-export([state_name/3]).
-export([handle_event/4]).
-export([terminate/3]).
-export([code_change/4]).

-export([compatible/1]).

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
    erlang:register(cipherl_alg, self()),
	{ok, state_name, #state{}}.

state_name(_EventType, _EventData, StateData) ->
	{next_state, state_name, StateData}.

handle_event(_EventType, _EventData, StateName, StateData) ->
	{next_state, StateName, StateData}.

terminate(Reason, _StateName, _StateData) ->
    logger:notice("~p terminating: ~p", [?MODULE, Reason]),
    gen_event:notify(cipherl_event, {cipherl_stopped, {?MODULE, Reason}}),
	ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
	{ok, StateName, StateData}.

%%-------------------------------------------------------------------------
%% @doc Check algos are compatible between sender and recipient nodes
%% @end
%%-------------------------------------------------------------------------
compatible(_) -> true.

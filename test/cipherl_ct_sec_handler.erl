-module(cipherl_ct_sec_handler).
-behaviour(gen_event).

-export([init/1, handle_event/2, terminate/2]).

init(_Args) ->
    {ok, []}.

handle_event({pid, Pid}, _State) when is_pid(Pid),(Pid =/= self()) ->
    logger:notice("Sec event will be sent to ~p", [Pid]),
    {ok, Pid};
handle_event(X, Pid) when is_pid(Pid) ->
    logger:notice("Sec event ~p will be sent to ~p", [X, Pid]),
	Pid ! X,
    {ok, Pid};
handle_event(X, State) ->
    logger:error("Invalid state ~p for message ~p received", [State, X]),
    {ok, State}.

terminate(_Args, _State) ->
    ok.
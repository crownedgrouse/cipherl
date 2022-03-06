-module(cipherl_server).
-behaviour(gen_server).

%% API.
-export([start_link/0]).

%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-export([format_status/2]).

-record(state, {
}).

-include("cipherl_records.hrl").

%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
	gen_server:start_link(?MODULE, [], []).

format_status(Opt, [_PDict,_State,_Data]) ->
    case Opt of
    terminate ->
        hidden;
    normal ->
        hidden
    end.

%% gen_server.

init([]) ->
    erlang:process_flag(trap_exit, true),
    erlang:register(cipherl_srv, self()),
	{ok, #state{}}.

handle_call({verify, Msg}, _From, State) ->
    Reply = gen_statem:call('cipherl_ks', {verify, Msg}),
    {reply,Reply,State};
handle_call({crypt, To, Msg, Pid}, _From, State) ->
    Node = safe_whereis(To),
    Reply = gen_statem:call('cipherl_ks', {crypt, Node, Msg, Pid}),
    {reply,Reply,State};
handle_call(Req, From, State) ->
    logger:info("~p~p call received from ~p: ~p", [?MODULE, self(), From, Req]),
	{reply, ignored, State}.

handle_cast(Msg, State) ->
    logger:info("~p~p cast received: ~p", [?MODULE, self(), Msg]),
	{noreply, State}.

handle_info(Info, State) ->
    logger:info("~p~p info received: ~p", [?MODULE, self(), Info]),
	{noreply, State}.

terminate(Reason, _State) ->
    logger:notice("~p terminating: ~p", [?MODULE, Reason]),
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.


%%-------------------------------------------------------------------------
%% @doc Get (and ensure) node from Destination Pid
%%-------------------------------------------------------------------------
safe_whereis(To) ->
    case To of
        {Reg, N} when is_atom(Reg),is_atom(N) -> N;
        To when is_atom(To) ->  case whereis(To) of
                                    undefined -> 'nonode@nohost';
                                    Pid -> node(Pid)
                                end;
        To when is_pid(To);is_reference(To);is_port(To) -> node(To);
        _ -> 'nonode@nohost'
   end.

-module(cipherl_fake).

-behaviour(gen_statem).

%% API.
-export([start/1, init/1, callback_mode/0, listen/3, code_change/4, terminate/3]).

start(Arg) ->
    gen_statem:start_link(?MODULE, Arg, []).

%% gen_statem.

callback_mode() ->
    state_functions.

init(Mode) ->
    erlang:register(cipherl_ks, self()),
    global:register_name({cipherl_ks, node()}, self()),
    {ok, listen, Mode}.

% Receive pubkey to use
listen(info, {pubkey, PubKey}, State) ->
    logger:info("pubkey received at fake side"),
    erlang:put(pubkey, PubKey),
    {next_state, listen, State};

% add_host_key_true_ko
listen(info, {cipherl_hello, Node, _, _, _}, add_host_key_true_ko) ->
    logger:info("add_host_key_true_ko at fake side"),
    % send an invalid auth msg
    case global:whereis_name({cipherl_ks, Node}) of
        undefined -> exit(cipherl_notfound); 
        Pid when is_pid(Pid) ->
            Pid ! {cipherl_auth, node(), erlang:monotonic_time(), <<>>, <<>>, <<>>}
    end,
    {next_state, listen, add_host_key_true_ko};

% add_host_key_false_ko
listen(info, {cipherl_hello, Node, _, _, _}, add_host_key_false_ko) ->
    logger:info("add_host_key_false_ko at fake side"),
    % send an invalid auth msg
    case global:whereis_name({cipherl_ks, Node}) of
        undefined -> exit(cipherl_notfound); 
        Pid when is_pid(Pid) ->
            PubKey = erlang:get(pubkey),
            Pid ! {cipherl_auth, node(), erlang:monotonic_time(), PubKey, <<"fakefake">>, <<"fakefake">>}
    end,
    {next_state, listen, add_host_key_false_ko}.

listen(_EventType, _EventData, StateName, add_host_key_true_ko) ->
    {next_state, StateName, add_host_key_true_ko}.

terminate(Reason, _StateName, _StateData) ->
    ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

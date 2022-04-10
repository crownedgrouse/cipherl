%%%-------------------------------------------------------------------
%%% File: cipherl.erl
%%% @author    Eric Pailleau <cipherl@crownedgrouse.com>
%%% @copyright 2022 crownedgrouse.com
%%% @doc
%%% Cipherl application
%%% @end
%%%
-module(cipherl).
-behaviour(application).

-export([start/2]).
-export([prep_stop/1, stop/1]).

-export([send/2, send/3, send_nosuspend/2, send_nosuspend/3]).
-export([decipher/1, verify/1]).

-include("cipherl_records.hrl").

start(_Type, _Args) ->
	cipherl_sup:start_link().

prep_stop(State) ->
    logger:notice("cipherl is stopping"),
    gen_event:notify(cipherl_event, {cipherl_stopped, ?MODULE}),
    State.

stop(_State) ->
    % Flushing logs
    logger:debug("flushing logs"),
    LogHandlers = lists:flatmap(fun(M) -> [{maps:get(id, M), maps:get(module, M)}] end, logger:get_handler_config()),
    lists:foreach(fun({N, M}) -> 
        case erlang:function_exported(M, filesync, 1) of 
            true  -> M:filesync(N) ; 
            false -> ok
        end
        end, LogHandlers),
    logger:alert("cipherl stopped"),
    c:flush().

%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Function for sending messages

send(Dest, Msg)
    ->
    CM = crypt(Dest, Msg),
    case CM of
        error -> error;
        _     -> erlang:send(Dest, CM),
                 Msg
    end.

send(Dest, Msg, nosuspend)
    ->
    CM = crypt(Dest, Msg),
    case CM of
        error -> error;
        _     -> erlang:send(Dest, CM, nosuspend)
    end;
send(Dest, Msg, noconnect)
    ->
    CM = crypt(Dest, Msg),
    case CM of
        error -> error;
        _     -> erlang:send(Dest, CM, noconnect)
    end.

send_nosuspend(Dest, Msg)
    ->
    CM = crypt(Dest, Msg),
    case CM of
        error -> error;
        _     -> erlang:send_nosuspend(Dest, CM)
    end.

send_nosuspend(Dest, Msg, Options)
    ->
    CM = crypt(Dest, Msg),
    case CM of
        error -> error;
        _     -> erlang:send_nosuspend(Dest, CM, Options)
    end.

%% Function for incoming messages

decipher(Msg)
    ->
    try
        case verify(Msg) of
            false -> throw(failing_decipher);
            true  -> ok
        end,
        gen_server:call(cipherl_srv, {uncrypt, Msg})
    catch
        _:R -> {cipherl_error, R}
    end.

verify(Msg) ->
    gen_server:call(cipherl_srv, {verify, Msg}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

crypt(Dest, Msg)
    ->    
    case gen_server:call(cipherl_srv, {crypt, Dest, Msg, self()}) of
        error      -> error;
        CM -> CM
    end.


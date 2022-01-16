-module(cipherl).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

-export([send/2, send/3, send_nosuspend/2, send_nosuspend/3]).
-export([verify/1]).

start(_Type, _Args) ->
	cipherl_sup:start_link().

stop(_State) ->
	ok.

%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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

verify(Msg) ->
    gen_server:call(cipherl_srv, {verify, Msg}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

crypt(Dest, Msg)
    ->    
    case gen_server:call(cipherl_srv, {crypt, Dest, Msg}) of
        error      -> error;
        CM -> CM
    end.


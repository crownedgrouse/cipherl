-module(cipherl).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

-export([send/2, send/3, send_nosuspend/2, send_nosuspend/3]).

start(_Type, _Args) ->
    %logger:set_primary_config(level, info),
	cipherl_sup:start_link().

stop(_State) ->
	ok.

%%% API %%%

send(_Dest, _Msg)
    ->
    ok.

send(_Dest, _Msg, nosuspend)
    ->
    ok;
send(_Dest, _Msg, noconnect)
    ->
    ok.

send_nosuspend(_Dest, _Msg)
    ->
    true.

send_nosuspend(_Dest, _Msg, _Options)
    ->
    true.

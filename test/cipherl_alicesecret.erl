-module(cipherl_alicesecret).
-behavior(cipherl_passphrase).
-export([passwd/1]).

passwd(_) ->  
    X = erlang:get(pkpp),
    {X, "alice"}.
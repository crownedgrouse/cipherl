%%%-------------------------------------------------------------------
%%% File:      cipherl_spassphrase.erl
%%% @author    Eric Pailleau <cipherl@crownedgrouse.com>
%%% @copyright 2022 crownedgrouse.com
%%% @doc
%%% Cipherl passphrase callback for behavior
%%% @end
%%%
-module(cipherl_passphrase).

-callback passwd(A :: atom()) -> 
    {dsa_pass_phrase, B :: string()} |
    {rsa_pass_phrase, B :: string()} |
    {ecdsa_pass_phrase, B :: string()}.
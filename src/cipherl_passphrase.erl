%%%-------------------------------------------------------------------
%%% File:      cipherl_spassphrase.erl
%%% @author    Eric Pailleau <cipherl@crownedgrouse.com>
%%% @copyright 2022 crownedgrouse.com
%%% @doc
%%% Cipherl passphrase callback for behavior
%%% @end
%%%
-module(cipherl_passphrase).

%% ee Public key algorithms at https://www.erlang.org/doc/man/ssh_app#supported
-callback passwd(KeyType:: atom(), Node :: node()) -> 
    {dsa_pass_phrase, PassPhrase :: string()} |
    {rsa_pass_phrase, PassPhrase :: string()} |
    {ecdsa_pass_phrase, PassPhrase :: string()}.
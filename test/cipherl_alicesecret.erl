-module(cipherl_alicesecret).
-behavior(cipherl_passphrase).
-export([passwd/2]).


passwd('ssh-dss', _) ->
    {dsa_pass_phrase, "alice"};
passwd('ssh-rsa', _) ->
    {rsa_pass_phrase, "alice"};
passwd('rsa-sha2-256', _) ->
    {rsa_pass_phrase, "alice"};
passwd('rsa-sha2-512', _) ->
    {rsa_pass_phrase, "alice"};
passwd('ecdsa-sha2-nistp384', _) ->
    {ecdsa_pass_phrase, "alice"};
passwd('ecdsa-sha2-nistp521', _) ->
    {ecdsa_pass_phrase, "alice"};
passwd('ecdsa-sha2-nistp256', _) ->
    {ecdsa_pass_phrase, "alice"};
passwd('ssh-ed448', _) ->
    {ecdsa_pass_phrase, "alice"};
passwd(KT, N) -> 
    logger:error("Unexpected arguments to get alice's passphrase: (~p, ~p)", [KT, N]),
    [].
-module(cipherl_bobsecret).
-behavior(cipherl_passphrase).
-export([passwd/2]).

passwd('ssh-dsa', _) ->
    {dsa_pass_phrase, "bobbob"};
passwd('ssh-rsa', _) ->
    {rsa_pass_phrase, "bobbob"};
passwd('rsa-sha2-256', _) ->
    {rsa_pass_phrase, "bobbob"};
passwd('rsa-sha2-512', _) ->
    {rsa_pass_phrase, "bobbob"};
passwd('ecdsa-sha2-nistp384', _) ->
    {ecdsa_pass_phrase, "bobbob"};
passwd('ecdsa-sha2-nistp521', _) ->
    {ecdsa_pass_phrase, "bobbob"};
passwd('ecdsa-sha2-nistp256', _) ->
    {ecdsa_pass_phrase, "bobbob"};
passwd('ssh-ed448', _) ->
    {ecdsa_pass_phrase, "bobbob"};
passwd(_, _) -> [].
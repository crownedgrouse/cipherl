-module(cipherl_bobsecret).
-behavior(cipherl_passphrase).
-export([passwd/1]).

-ifdef(KEYTYPE).
    keytype() -> ?KEYTYPE.
-else.
    keytype() ->  rsa_pass_phrase.
-endif.

passwd(_) -> case keytype() of
                none -> [];
                X    -> {X, "bobbob"}
             end.
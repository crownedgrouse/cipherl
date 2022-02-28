-module(cipherl_passphrase).

-callback passwd(A :: atom()) -> B :: list().
-module(cipherl_passphrase).

-callback passwd(A :: atom()) -> 
    {dsa_pass_phrase, B :: string()} |
    {rsa_pass_phrase, B :: string()} |
    {ecdsa_pass_phrase, B :: string()}.
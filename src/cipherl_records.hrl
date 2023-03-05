
%%-------------------------------------------------------------------------
%% @doc Message sent to new comer
%%      Newcomer must reply with a cipherl_auth message
%% @end
%%-------------------------------------------------------------------------
-record(cipherl_hello, 
            {node   :: atom()     % Sender node
            ,nonce  :: integer()  % Sender nonce
            ,pubkey :: <<>>       % Sender pubkey
            ,algos  :: list()     % ssh:default_algorithms()
            }
        ).

%%-------------------------------------------------------------------------
%% @doc Generic message
%% @end
%%-------------------------------------------------------------------------
-record(cipherl_msg,
            {node    :: atom()
            ,payload :: <<>>
            ,signed  :: <<>>
            }
       ).

%%-------------------------------------------------------------------------
%% @doc Message sent back to node sending a Hello
%%      - Payload is crypted with pubkey of Node having sent Hello
%%      - Signature is a proof that Node is private key owner
%% @end
%%-------------------------------------------------------------------------
-record(cipherl_auth,
            {node     :: atom()
            ,nonce    :: integer()
            ,chal     :: binary()  % cîpherl_chal record crypted with my Private key
            }
       ).

%%-------------------------------------------------------------------------
%% @doc Challenge record
%%      Record to be sent crypted with my private key as part 
%%      of cipherl_auth message  (chal entry).
%%      Second nonce MUST be the same than nonce set in cipherl_auth 
%%      message (nonce entry).
%%      Challenging Node will need to check that its own chal record 
%%      crypted with public key
%% @end
%%-------------------------------------------------------------------------
-record(cipherl_chal,
            { node    :: atom()      % Node having sent Hello
            , nonce   :: integer()   % Nonce received in Hello message 
            , nonce   :: integer()   % Repeat Nonce of cipherl_auth (used as a non replay protection)
            }
       ).
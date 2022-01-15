
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
            {payload :: <<>>
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
            {cipherl_hello = #cipherl_hello{}
            ,cipherl_msg   = #cipherl_msg{}
            }
       ).

%%-------------------------------------------------------------------------
%% @doc Challenge to be sent back 
%%      Term to be sent back as crypted payload into a cipherl_auth message.
%%      Recipient check that node is itself and nonce was the one used.
%% @end
%%-------------------------------------------------------------------------
-record(cipherl_chal,
            { node    :: atom()      % Node having sent Hello
            , nonce   :: integer()   % Nonce received from upper node in Hello message (used as a non replay protection)
            , random  :: term()      % Anything random to let payload unpredictable. Empty is an error.
            }
       ).
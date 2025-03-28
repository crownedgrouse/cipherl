%%%-------------------------------------------------------------------
%%% File: cipherl_conf_SUITE.erl
%%% @author    Eric Pailleau <cipherl@crownedgrouse.com>
%%% @copyright 2022 crownedgrouse.com
%%% @doc
%%% Cipherl common tests - configuration suite.
%%% @end
%%%-------------------------------------------------------------------
 -module(cipherl_conf_SUITE).

 -compile([nowarn_export_all,export_all]).

 -include_lib("common_test/include/ct.hrl").

 -on_load(onload/0).

-define('_'(A, B), io_lib:format(A, B)).

-define(value(Key,Config), proplists:get_value(Key,Config)).

-define(ERROR_REL, "cipherl common test requires 'peer' module, available starting OTP-25.").
%% Requires 'peer' module available starting OTP-25
-ifdef(OTP_RELEASE).
  %% OTP 25 or higher
  -if(?OTP_RELEASE >= 25).
     onload() -> ok.
  -else.
     onload() -> erlang:display(?ERROR_REL), error.
  -endif.
-else.
  %% OTP 20 or lower.
     onload() -> erlang:display(?ERROR_REL), error.
-endif.

-ifdef(OTP_RELEASE).
  %% OTP 25 or higher : function documented
  -if(?OTP_RELEASE >= 25).
    -define(PUBKEY(X), ssh_file:extract_public_key(X)).
  -else.
    -define(PUBKEY(X), ssh_transport:extract_public_key(X)).
  -endif.
-else.
  %% OTP 20 or lower.
    -define(PUBKEY(X), ssh_transport:extract_public_key(X)).
-endif.

 %%--------------------------------------------------------------------
 %% Function: suite() -> Info
 %% Info = [tuple()]
 %%--------------------------------------------------------------------
 suite() ->
     [{timetrap,{seconds,30}}].

 %%--------------------------------------------------------------------
 %% Function: init_per_suite(Config0) ->
 %%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %%--------------------------------------------------------------------
 init_per_suite(Config) -> 
     %ct:print(io_lib:format("Suite config  : ~p", [Config])),
     %L = [rsa, 'dsa.1024', 'ecdsa.256', 'ecdsa.384', 'ecdsa.521', 'ecdsa.25519'], % TODO fix
     %L = ['ecdsa.256', 'ecdsa.384', 'ecdsa.521', 'ecdsa.25519'], % TODO fix
     %L = ['ecdsa.256', 'ecdsa.384', 'ecdsa.521'], 
     L = ['rsa'], % overide if required or wanting limit list
     % Choose randomly a SSH key type
     Offset = erlang:ceil(rand:uniform() * erlang:length(L)),
     RandSshType = erlang:element(Offset, erlang:list_to_tuple(L)),
     ct:pal(?_("SSH Key Type: ~p", [RandSshType])),
     
     % Configure applications
     application:stop(ssh),
     application:set_env([  
        {kernel,
                [{logger_level, all} % Set to all for more verbosity
                ,{dist_auto_connect, once}
                ,{logger,
                    [{handler, default, logger_std_h,
                    #{ formatter => {logger_formatter, #{ }}}}]
                 }
                ]
            },
            {ssh, [{modify_algorithms, 
                  [{append, [{kex,['diffie-hellman-group1-sha1','diffie-hellman-group14-sha256']}]}
                  ,{prepend, [{public_key,[pkmap(RandSshType)]}]}
                  ]
                  }
                ]
            }
        ]),
     application:start(ssh),

    case lists:member(pkmap(RandSshType), ssh_pubkey_alg()) of
        false -> ct:pal(?_("~p not found in ssh:default_algorithms. Skipping", [pkmap(RandSshType)])),
                 {skip, ssh_algo_undeclared};
        true  ->     
             % Compile Bob's passphrase module
             Macro = pktype(RandSshType),
             Path  = code:where_is_file("cipherl_bobsecret.erl"),
             Dir   = filename:dirname(Path),
             File  = filename:join(Dir, filename:basename(Path, ".erl")),
             case compile:file(File, [{debug_info_key,"bobsecretpassphrase"},{d, 'KEYTYPE', Macro}, return_errors,{outdir, Dir}]) of
                {error, ErrorList, WarningList} 
                    -> ct:pal(?_("Compilating ~p :~nErros: ~p~nWarnings: ~p", [File, ErrorList, WarningList])),
                       ct:fail(cipherl_bobsecret);
                {ok, _} 
                    -> ok
             end,
             [{sshtype, RandSshType} | Config]
    end.

 %%--------------------------------------------------------------------
 %% Function: end_per_suite(Config0) -> term() | {save_config,Config1}
 %% Config0 = Config1 = [tuple()]
 %%--------------------------------------------------------------------
 end_per_suite(_Config) ->
     ok.

 %%--------------------------------------------------------------------
 %% Function: init_per_group(GroupName, Config0) ->
 %%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
 %% GroupName = atom()
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %%--------------------------------------------------------------------
 init_per_group(add_host_key, Config)
    ->
    ct:comment("<a href='https://github.com/crownedgrouse/cipherl/wiki/1---Configuration#add_host_key'>add_host_key</a>"),
    ST = proplists:get_value(sshtype, Config),
    AD = filename:join(code:priv_dir(cipherl), "test/alice/.ssh/"),
    BD = filename:join(code:priv_dir(cipherl), "test/bob/.ssh/"),
    PK = pkmap(ST),
    PKPP = pkppmap(ST),
    persistent_term:put(pkpp, PKPP),

    % Add Bob's pubkey in known_hosts
    file:delete(filename:join(AD, "known_hosts")),
    file:delete(filename:join(BD, "known_hosts")),
    active_key(AD, ST),
    active_key(BD, ST),
    BPrivKey = 
    case ssh_file:user_key(PK, [{user_dir, BD},{PKPP,"bobbob"}]) of 
        {ok, P} ->  P ;
        {error, Error} -> ct:fail(Error), []
    end,
    BPubKey = ssh_file:extract_public_key(BPrivKey),
    %ct:pal(?_("Adding Bob's pubkey in Alice known_hosts file: ~p", [BPubKey])),
    ok = ssh_file:add_host_key(net_adm:localhost(), 22, BPubKey, [{user_dir, AD}]),
    Config ++ [{cipherl_ct, [{mod_passphrase,cipherl_alicesecret}, {ssh_dir,user},{check_rs, false},{user_dir, AD} ,{ssh_pubkey_alg, PK}]}];
 init_per_group(_GroupName, Config) ->
    %ct:print(io_lib:format("Group config ~p : ~p", [_GroupName, Config])),
     Config.

 %%--------------------------------------------------------------------
 %% Function: end_per_group(GroupName, Config0) ->
 %%               term() | {save_config,Config1}
 %% GroupName = atom()
 %% Config0 = Config1 = [tuple()]
 %%--------------------------------------------------------------------
 end_per_group(add_host_key, Config)
    ->
    ST = proplists:get_value(sshtype, Config),
    AD = filename:join(code:priv_dir(cipherl), "test/alice/.ssh/"),
    BD = filename:join(code:priv_dir(cipherl), "test/bob/.ssh/"),
    unactive_key(AD, ST),
    unactive_key(BD, ST),
    ok;
 end_per_group(_GroupName, _Config) 
    -> ok.

 %%--------------------------------------------------------------------
 %% Function: init_per_testcase(TestCase, Config0) ->
 %%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
 %% TestCase = atom()
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %%--------------------------------------------------------------------
 init_per_testcase(_TestCase, Config) ->
     %ct:pal(?_("Testcase config ~p : ~p", [_TestCase, Config])),
     Config.

 %%--------------------------------------------------------------------
 %% Function: end_per_testcase(TestCase, Config0) ->
 %%               term() | {save_config,Config1} | {fail,Reason}
 %% TestCase = atom()
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %%--------------------------------------------------------------------
 end_per_testcase(_TestCase, _Config) ->
     application:stop(cipherl),
     ok.

 %%--------------------------------------------------------------------
 %% Function: groups() -> [Group]
 %% Group = {GroupName,Properties,GroupsAndTestCases}
 %% GroupName = atom()
 %% Properties = [parallel | sequence | Shuffle | {RepeatType,N}]
 %% GroupsAndTestCases = [Group | {group,GroupName} | TestCase]
 %% TestCase = atom()
 %% Shuffle = shuffle | {shuffle,{integer(),integer(),integer()}}
 %% RepeatType = repeat | repeat_until_all_ok | repeat_until_all_fail |
 %%              repeat_until_any_ok | repeat_until_any_fail
 %% N = integer() | forever
 %%--------------------------------------------------------------------
 groups() ->
     [{add_host_key,     [sequence], [add_host_key_true_ok, add_host_key_true_ko, add_host_key_false_ok, add_host_key_false_ko]}
     ,{hidden_node,      [sequence], [hidden_node_true, hidden_node_false]}
     ,{mod_passphrase,   [sequence], [mod_passphrase_none_ok, mod_passphrase_none_ko, mod_passphrase_invalid, mod_passphrase_ok, mod_passphrase_ko]}
     ,{rpc_enabled,      [sequence], [rpc_enabled_true, rpc_enabled_true_pending, rpc_enabled_false]}
     ,{security_handler, [sequence], [security_handler_valid, security_handler_invalid, security_handler_missing]}
     ,{system_dir,       [sequence], [system_dir_ok, system_dir_ko]}
     ,{ssh_dir,          [sequence], [ssh_dir_system, ssh_dir_user]}
     ,{ssh_pubkey_alg,   [sequence], [ssh_pubkey_alg_missing, ssh_pubkey_alg_invalid]}
     ,{user_dir,         [sequence], [user_dir_ok, user_dir_ko]}
     ].

 %%--------------------------------------------------------------------
 %% Function: all() -> GroupsAndTestCases | {skip,Reason}
 %% GroupsAndTestCases = [{group,GroupName} | TestCase]
 %% GroupName = atom()
 %% TestCase = atom()
 %% Reason = term()
 %%--------------------------------------------------------------------
 all() -> 
     [{group, add_host_key}
     %,{group, hidden_node}
     %,{group, mod_passphrase}
     %,{group, rpc_enabled}
     %,{group, security_handler}
     %,{group, system_dir}
     %,{group, ssh_dir}
     %,{group, ssh_pubkey_alg}
     %,{group, user_dir}
     ].

 %%--------------------------------------------------------------------
 %% Function: TestCase() -> Info
 %% Info = [tuple()]
 %%--------------------------------------------------------------------
add_host_key_true_ok() 
     ->  test_case_common([]).
add_host_key_true_ko() 
     ->  test_case_common([]).
add_host_key_false_ok() 
     ->  test_case_common([]).
add_host_key_false_ko() 
     ->  test_case_common([]).
hidden_node_true() 
     ->  test_case_common([]).
hidden_node_false() 
     ->  test_case_common([]).
mod_passphrase_none_ok() 
     ->  test_case_common([]).
mod_passphrase_none_ko() 
     ->  test_case_common([]).
mod_passphrase_invalid() 
     ->  test_case_common([]).
mod_passphrase_ok() 
     ->  test_case_common([]).
mod_passphrase_ko() 
     ->  test_case_common([]).
rpc_enabled_true() 
     ->  test_case_common([]).
rpc_enabled_true_pending() 
     ->  test_case_common([]).
rpc_enabled_false() 
     ->  test_case_common([]).
security_handler_valid() 
     ->  test_case_common([]).
security_handler_invalid() 
     ->  test_case_common([]).
security_handler_missing() 
     ->  test_case_common([]).
system_dir_ok() 
     ->  test_case_common([]).
system_dir_ko() 
     ->  test_case_common([]).
ssh_dir_system() 
     ->  test_case_common([]).
ssh_dir_user() 
     ->  test_case_common([]).
ssh_pubkey_alg_missing() 
     ->  test_case_common([]).
ssh_pubkey_alg_invalid() 
     ->  test_case_common([]).
user_dir_ok() 
     ->  test_case_common([]).
user_dir_ko() 
     ->  test_case_common([]).

%%--------------------------------------------------------------------
%% Replace an option in common testcase configuration
%%--------------------------------------------------------------------
test_case_common(X) ->
    I = [{timetrap,{seconds,30}}
        ,{require, cipherl}
        ,{default_config, cipherl, []}
        ], 
    Fun = fun(T, Acc) -> { [], lists:keyreplace(erlang:element(1,T), 1, lists:sort(Acc), T)} end,
    {_, TC}= lists:mapfoldl(Fun, I, X),
    %ct:pal(?_("Debug : ~p", [TC])),
    TC.

 %%--------------------------------------------------------------------
 %% Function: TestCase(Config0) ->
 %%               ok | exit() | {skip,Reason} | {comment,Comment} |
 %%               {save_config,Config1} | {skip_and_save,Reason,Config1}
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %% Comment = term()
 %%--------------------------------------------------------------------
add_host_key_true_ok(Config) ->  
    ct:pal(?_("=== ~p ===", [?FUNCTION_NAME])),
    ct:comment("Alice add Bob's public key in known_hosts and allow Bob to connect"),
    % stop cipherl at Alice
    application:stop(cipherl),
    Conf = [{add_host_key, true}] ++ 
           proplists:get_value(cipherl_ct, Config, []) ,
    ct:pal(?_("Config at Alice's side: ~p", [Conf])),
    % remove current known_hosts created by init_per_group
    AD = proplists:get_value(user_dir, Conf),
    KH = filename:join(AD, "known_hosts"),
    % ct:pal(?_("Alices's KH file : ~p",[KH])),
    ok = file:delete(KH),
    ok = file:write_file(KH, ""),
    %ok = file:change_mode(KH, 8#00644),
    % start a peer Bob
    {ok, Peer, Node} = ?CT_PEER(#{name => bob, shutdown => close, peer_down => crash, connection => standard_io}),
    % launch cipherl at Bob side with a config set before
    PKA = proplists:get_value(ssh_pubkey_alg, Conf),
    ct:log(?_("pubkey: ~p", [PKA])),
    BD  = filename:join(code:priv_dir(cipherl), "test/bob/.ssh/"),
    % KHB = filename:join(BD, "known_hosts"),
    % ct:pal(?_("Bob's KH file : ~p ",[KHB])),
    _C0 = peer:call(Peer, application, set_env, [cipherl, ssh_dir, user, [{persistent, true}]]),
    _C1 = peer:call(Peer, application, set_env, [cipherl, user_dir, BD, [{persistent, true}]]),
    _C2 = peer:call(Peer, application, set_env, [cipherl, ssh_pubkey_alg, PKA, [{persistent, true}]]),
    _C3 = peer:call(Peer, application, set_env, [cipherl, mod_passphrase, 'cipherl_bobsecret', [{persistent, true}]]),
    _C4 = peer:call(Peer, code, add_path, [filename:dirname(code:where_is_file("cipherl.app"))]),
    _C5 = peer:call(Peer, code, add_path, [filename:dirname(code:where_is_file("cipherl_bobsecret.erl"))]),
    _C6 = peer:call(Peer, application, set_env, [ssh, modify_algorithms, 
      [{append, [{kex,['diffie-hellman-group1-sha1']}]}
      ,{prepend, [{public_key,[PKA]}]}
      ], [{persistent, true}]]),
    _C7 = peer:call(Peer, application, set_env, [cipherl, check_rs, false, [{persistent, true}]]),
    _C8 = peer:call(Peer, application, set_env, [cipherl, add_host_key, true, [{persistent, true}]]),
    _CLast = peer:call(Peer, application, load, [cipherl]),
    ct:pal(?_("Config at Bob's side: ~p", [lists:sort(peer:call(Peer, application, get_all_env, [cipherl]))])),
    BS = peer:call(Peer, application, ensure_all_started, [cipherl]),
    %ct:pal(?_("Cipherl start at Bob side: ~p", [BS])),
    % start cipherl at Alice  
    start_with_handler(Conf),
    % Affect current cookie to Bob
    peer:call(Peer, erlang, set_cookie, [erlang:get_cookie()]),
    erlang:set_cookie(Node, erlang:get_cookie()),
    peer:call(Peer, net_adm, ping, [node()]),
    net_adm:ping(Node),
    % verify Bob is recorded in known_host
    receive 
        {authorized_host, _} 
            -> ct:log(?_("~p was authorized in known_hosts", [Node])),
               % verify Bob is allowed to connect
               ok;
        Other 
            -> ct:log(?_("Received : ~p", [Other])),
               ct:fail({unexpected_msg, Other})
    end,
    peer:stop(Peer),
    ok.
add_host_key_true_ko(Config) ->  %% TODO
    ct:pal(?_("=== ~p ===", [?FUNCTION_NAME])),
    ct:comment("Alice do not add Bob in known_hosts due to invalid public key"),
    %%  Start a peer node bob with a fake cipherl sending crap
    % Set config for Alice
    Conf = [{add_host_key, true}] ++ 
           proplists:get_value(cipherl_ct, Config, []) ,
    ct:log(?_("Cipherl config : ~p", [Conf])),
    % Starting Bob 
    {ok, Peer, Node} = ?CT_PEER(#{name => bob, shutdown => close, peer_down => crash, connection => standard_io}),
    ct:log(?_("PeerPid : ~p~nNode    : ~p", [Peer, Node])),
    {ok, _ } = peer:call(Peer, cipherl_fake, start, [add_host_key_true_ko]),
    % Start Alice
    start_with_handler(Conf),
    peer:call(Peer, net_adm, ping, [node()]),
    net_adm:ping(Node),

    receive 
        {rogue_node, N} -> ct:log(?_("received expected rogue node event for ~p", [N])), ok ;
        Msg ->  ct:pal(?_("received: ~p", [Msg])),
                ct:fail(unexpected_msg)
        after 10000 -> ct:fail(timeout)
    end,    
    peer:stop(Peer),
    ok.
add_host_key_false_ok(Config) -> 
    ct:pal(?_("=== ~p ===", [?FUNCTION_NAME])),
    ct:comment("Alice has Bob's public key already recorded and allow Bob to try authentication"),
    % Set config for Alice
    Conf = [{add_host_key, false}] ++ 
           proplists:get_value(cipherl_ct, Config, []) ,
    ct:log(?_("Cipherl config : ~p", [Conf])),
    start_with_handler(Conf),
    % Starting Bob 
    {ok, Peer, Node} = ?CT_PEER(#{name => bob, shutdown => halt, peer_down => crash}),
    ct:log(?_("PeerPid : ~p~nNode    : ~p", [Peer, Node])),

    receive 
        {authorized_host, _} 
            -> ct:log(?_("~p is known in known_hosts", [Node]));
        Other 
            -> ct:fail({unexpected_msg, Other})
    after 5000 -> ct:fail(timeout)
    end,
    peer:stop(Peer),
    ok.
add_host_key_false_ko(Config) ->  
    ct:pal(?_("=== ~p ===", [?FUNCTION_NAME])),
    ct:comment("Alice has Bob's public key already recorded and refuse connection to Bob due to invalid challenge"),
    %%  Start a peer node bob with a fake cipherl sending crap
    % Set config for Alice
    Conf = [{add_host_key, false}] ++ 
           proplists:get_value(cipherl_ct, Config, []) ,
    ct:log(?_("Cipherl config : ~p", [Conf])),
    % Starting Bob 
    {ok, Peer, Node} = ?CT_PEER(#{name => bob, shutdown => close, peer_down => crash, connection => standard_io}),
    ct:log(?_("PeerPid : ~p~nNode    : ~p", [Peer, Node])),
    {ok, _ } = peer:call(Peer, cipherl_fake, start, [add_host_key_false_ko]),
    %  set a valid public key to use at fake side
    BD  = filename:join(code:priv_dir(cipherl), "test/bob/.ssh/"),
    KT = proplists:get_value(ssh_pubkey_alg, Conf),
    PT = case KT of
            'ssh-rsa' -> rsa_pass_phrase ;
            Z -> Z
         end,
    Args = [{user_dir, BD}, {PT, "bobbob"}],
    Private = 
            case ssh_file:user_key(KT, Args) of
                {ok, Priv}      -> Priv;
                {error, Reason} -> 
                    ct:log(?_("ssh_file:user_key error : ~p", [Reason])),
                    ct:fail(privatekey_extract)
            end,
    Public = ?PUBKEY(Private),
    peer:call(Peer, erlang, send, [cipherl_ks, {pubkey, Public}]),
    % Start Alice
    start_with_handler(Conf),
    peer:call(Peer, net_adm, ping, [node()]),

    receive 
        {authorized_host,_} -> ok ;
        Msg1 -> 
            ct:log(?_("received: ~p", [Msg1])),
            ct:fail(unexpected_msg)
        after 10000 -> ct:fail(timeout)
    end,
    receive 
        {rogue_node, N} -> ct:log(?_("received expected rogue node event for ~p", [N])), ok ;
        Msg2 -> 
            ct:log(?_("received: ~p", [Msg2])),
            ct:fail(unexpected_msg)
        after 10000 -> ct:fail(timeout)
    end,    
    peer:stop(Peer),
    ok.
hidden_node_true(_Config) ->  ok.
hidden_node_false(_Config) ->  ok.
mod_passphrase_none_ok(_Config) ->  ok.
mod_passphrase_none_ko(_Config) ->  ok.
mod_passphrase_invalid(_Config) ->  ok.
mod_passphrase_ok(_Config) ->  ok.
mod_passphrase_ko(_Config) ->  ok.
rpc_enabled_true(_Config) ->  ok.
rpc_enabled_true_pending(_Config) ->  ok.
rpc_enabled_false(_Config) ->  ok.
security_handler_valid(_Config) ->  ok.
security_handler_invalid(_Config) ->  ok.
security_handler_missing(_Config) ->  ok.
system_dir_ok(_Config) ->  ok.
system_dir_ko(_Config) ->  ok.
ssh_dir_system(_Config) ->  ok.
ssh_dir_user(_Config) ->  ok.
ssh_pubkey_alg_missing(_Config) ->  ok.
ssh_pubkey_alg_invalid(_Config) ->  ok.
user_dir_ok(_Config) ->  ok.
user_dir_ko(_Config) ->  ok.

%%%%%%%%%%%%%%%%%%%%%%%%% LOCAL FUNCTIONS %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%-------------------------------------------------------------------------
%% @doc Map private key filename to public key also
%% @end
%%-------------------------------------------------------------------------
pkmap(rsa)           -> 'ssh-rsa' ;
pkmap('dsa.1024')    -> 'ssh-dss' ;
pkmap('ecdsa.256')   -> 'ecdsa-sha2-nistp256' ;
pkmap('ecdsa.384')   -> 'ecdsa-sha2-nistp384' ;
pkmap('ecdsa.521')   -> 'ecdsa-sha2-nistp521' ;
pkmap('ecdsa.25519') -> 'ssh-ed25519' ;
pkmap(X)   -> ct:pal(?_("pkmap arg not found: ~p", [X])),
              exit(1).


%%-------------------------------------------------------------------------
%% @doc Map private key filename to public key also
%% @end
%%-------------------------------------------------------------------------
pkppmap(rsa)           -> 'rsa_pass_phrase' ;
pkppmap('dsa.1024')    -> 'dsa_pass_phrase' ;
pkppmap('ecdsa.256')   -> 'ecdsa_pass_phrase' ;
pkppmap('ecdsa.384')   -> 'ecdsa_pass_phrase' ;
pkppmap('ecdsa.521')   -> 'ecdsa_pass_phrase' ;
pkppmap('ecdsa.25519') -> 'ecdsa_pass_phrase' ;
pkppmap(X)   -> ct:pal(?_("pkppmap arg not found: ~p", [X])),
              exit(1).

%%-------------------------------------------------------------------------
%% @doc Map public key to compilation macro for passphase
%% @end
%%-------------------------------------------------------------------------
pktype('ssh-rsa') -> rsa;
pktype('ssh-dss') -> dsa;
pktype('ecdsa-sha2-nistp256') -> ecdsa;
pktype('ecdsa-sha2-nistp384') -> ecdsa;
pktype('ecdsa-sha2-nistp521') -> ecdsa;
pktype(_) -> none.

%%-------------------------------------------------------------------------
%% @doc Map key type to id file name
%%    USERDIR/id_dsa
%%    USERDIR/id_rsa
%%    USERDIR/id_ecdsa
%%    USERDIR/id_ed25519
%%    USERDIR/id_ed448
%% @end
%%-------------------------------------------------------------------------
pkfile(rsa)           -> "id_rsa" ;
pkfile('dsa.1024')    -> "id_dsa";
pkfile('ecdsa.256')   -> "id_ecdsa" ;
pkfile('ecdsa.384')   -> "id_ecdsa" ;
pkfile('ecdsa.521')   -> "id_ecdsa" ;
pkfile('ecdsa.25519') -> "id_ed25519" ;
pkfile(_) -> "".

%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
active_key(Dir, X = rsa)
    -> ok = active_keyfile(key_path(Dir, "id_rsa.key"), pkfile(X));
active_key(Dir, X = 'dsa.1024') 
    -> ok = active_keyfile(key_path(Dir, "id_dsa.1024"), pkfile(X));
active_key(Dir, X = 'ecdsa.256')
    -> ok = active_keyfile(key_path(Dir, "id_ecdsa.256"), pkfile(X));
active_key(Dir, X = 'ecdsa.384')
    -> ok = active_keyfile(key_path(Dir, "id_ecdsa.384"), pkfile(X));
active_key(Dir, X = 'ecdsa.521')
    -> ok = active_keyfile(key_path(Dir, "id_ecdsa.521"), pkfile(X));
active_key(Dir, X = 'ecdsa.25519')
    -> ok = active_keyfile(key_path(Dir, "id_ecdsa.25519"), pkfile(X));
active_key(_, X)
    -> ct:pal(?_("active_key arg not found: ~p", [X])),
       exit(1).

active_keyfile(File, ID)
    -> % Remove any former link
       Dir = filename:dirname(File),
       IDFile = key_path(Dir, ID),
       % Remove any former id file
       file:delete(key_path(Dir, "id_rsa")),
       file:delete(key_path(Dir, "id_dsa")),
       file:delete(key_path(Dir, "id_ecdsa")),
       file:delete(key_path(Dir, "id_ed25519")),
       case file:copy(File, IDFile) of
        {ok, _} -> 
            file:change_mode(IDFile, 8#00400),
             ok ;
        {error, Reason} ->
            ct:pal(?_("cannot copy key as id file: ~p", [Reason]))
       end.

%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
unactive_key(Dir, rsa)
    -> ok = unactive_key(key_path(Dir, "id_rsa.key"));
unactive_key(Dir, 'dsa.1024')
    -> ok = unactive_key(key_path(Dir, "id_dsa.1024"));
unactive_key(Dir, 'ecdsa.256')
    -> ok = unactive_key(key_path(Dir, "id_ecdsa.256"));
unactive_key(Dir, 'ecdsa.384')
    -> ok = unactive_key(key_path(Dir, "id_ecdsa.384"));
unactive_key(Dir, 'ecdsa.521')
    -> ok = unactive_key(key_path(Dir, "id_ecdsa.521"));
unactive_key(Dir, 'ecdsa.25519')
    -> ok = unactive_key(key_path(Dir, "id_ecdsa.25519"));
unactive_key(_, X)
    -> ct:pal(?_("unactive_key arg not found: ~p", [X])),
       exit(1).


unactive_key(_FileOrLink)
    -> 
        %case  file:read_link(FileOrLink) of
        %       {error,_} -> unactive_key(link_path(FileOrLink)) ;
        %       {ok, _}   -> file:delete(FileOrLink)
        %end
        ok.

%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
key_path(Dir, File)
    -> filename:join([Dir, File]).

link_path(KeyPath)
    -> 
      filename:join(filename:dirname(KeyPath), filename:basename(KeyPath, filename:extension(KeyPath))).

%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
start_with_handler(Conf)
    ->
    application:stop(cipherl),
    receive _ -> ok 
        after 2000 -> ok
    end,
    application:unload(cipherl), % Keep otherwise conf is not applied
    ok = application:set_env([{cipherl, Conf}]),
    {ok, _} = application:ensure_all_started(cipherl),
    % Add handler
    ok = gen_event:add_sup_handler(cipherl_event, cipherl_ct_sec_handler, []),
    gen_event:sync_notify(cipherl_event, {pid, self()}),
    ok.

%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
ssh_pubkey_alg()
    -> 
    case lists:keyfind(public_key, 1, ssh:default_algorithms()) of
         false -> [];
         {public_key, L} -> L       
    end.
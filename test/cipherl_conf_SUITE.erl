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
    % L = [rsa, 'dsa.1024', 'ecdsa.256', 'ecdsa.384', 'ecdsa.521', 'ecdsa.25519'],
     L = [rsa],
     Offset = erlang:ceil(rand:uniform() * erlang:length(L)),
     RandSshType = erlang:element(Offset, erlang:list_to_tuple(L)),
     ct:pal(?_("SSH Key Type: ~p", [RandSshType])),
     application:stop(ssh),
     application:set_env([  {kernel,
                                [ {logger_level, all}
                                ,{logger,
                                    [{handler, default, logger_std_h,
                                    #{ formatter => {logger_formatter, #{ }}}}]
                                 }
                                ]
                            },
                            {ssh, [{modify_algorithms, 
                                  [{append, [{kex,['diffie-hellman-group1-sha1']}]}
                                  ,{prepend, [{public_key,['ssh-rsa']}]}
                                  ]
                                  }
                                ]
                            }
                        ]),
     application:start(ssh),
     [{sshtype, RandSshType} | Config].

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

    % Add Bob's pubkey in known_hosts
    file:delete(filename:join(AD, "known_hosts")),
    active_key(AD, ST),
    active_key(BD, ST),
    {ok, BPrivKey} = ssh_file:user_key(PK, [{user_dir, BD},{rsa_pass_phrase,"bobbob"}]),
    BPubKey = ssh_file:extract_public_key(BPrivKey),
    ok = ssh_file:add_host_key(net_adm:localhost(), 22, BPubKey, [{user_dir, AD}]),
    Config ++ [{cipherl_ct, [{user_dir, AD} ,{ssh_pubkey_alg, PK}]}];
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
     [{add_host_key,     [parallel], [add_host_key_true_ok, add_host_key_true_ko, add_host_key_false_ok, add_host_key_false_ko]}
     ,{hidden_node,      [parallel], [hidden_node_true, hidden_node_false]}
     ,{mod_passphrase,   [parallel], [mod_passphrase_none_ok, mod_passphrase_none_ko, mod_passphrase_invalid, mod_passphrase_ok, mod_passphrase_ko]}
     ,{rpc_enabled,      [parallel], [rpc_enabled_true, rpc_enabled_true_pending, rpc_enabled_false]}
     ,{security_handler, [parallel], [security_handler_valid, security_handler_invalid, security_handler_missing]}
     ,{system_dir,       [parallel], [system_dir_ok, system_dir_ko]}
     ,{ssh_dir,          [parallel], [ssh_dir_system, ssh_dir_user]}
     ,{ssh_pubkey_alg,   [parallel], [ssh_pubkey_alg_missing, ssh_pubkey_alg_invalid]}
     ,{user_dir,         [parallel], [user_dir_ok, user_dir_ko]}
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
     ->  test_case_common([{default_config, cipherl, [{add_host_key, true}]}]).
add_host_key_true_ko() 
     ->  test_case_common([{default_config, cipherl, [{add_host_key, true}]}]).
add_host_key_false_ok() 
     ->  test_case_common([{default_config, cipherl, [{add_host_key, false}]}]).
add_host_key_false_ko() 
     ->  test_case_common([{default_config, cipherl, [{add_host_key, false}]}]).
hidden_node_true() 
     ->  test_case_common([{default_config, cipherl, [{hidden_node, true}]}]).
hidden_node_false() 
     ->  test_case_common([{default_config, cipherl, [{hidden_node, false}]}]).
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
    I = [{timetrap,{seconds,60}}
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
add_host_key_true_ok(_Config) ->  
    ct:comment("Alice add Bob's public key in known_hosts and allow Bob to connect"),
    % remove current known_hosts created by init_per_group
    % stop cipherl at Alice
    % start a peer Bob
    % launch cipherl at Bob side with config
    % start cipherl at Alice
    % verify Bob is recorded in known_host
    % verify Bob is allowed to connect
    ok.
add_host_key_true_ko(_Config) ->  
    ct:comment("Alice do not add Bob in known_hosts due to invalid public key"),
    ok.
add_host_key_false_ok(Config) -> 
    ct:comment("Alice has Bob's public key already recorded and allow Bob to try authentication"),
    % Set config for Alice
    Conf = ct:get_config(cipherl) ++ proplists:get_value(cipherl_ct, Config, []),
    %ct:log(?_("Cipherl config : ~p", [Conf])),
    start_with_handler(Conf),
    % Starting Bob 
    {ok, Peer, Node} = ?CT_PEER(#{name => bob, shutdown => halt, peer_down => crash}),
    %ct:log(?_("PeerPid : ~p~nNode    : ~p", [Peer, Node])),

    receive 
        {authorized_host, Node} 
            -> ct:pal(?_("~p was authorized in known_hosts", [Node])),
               peer:stop(Peer);
        Other 
            -> ct:fail({unexpected_msg, Other})
    after 5000 -> ct:fail(timeout)
    end,
    ok.
add_host_key_false_ko(_Config) ->  
    ct:comment("Alice has Bob's public key already recorded and refuse connection to Bob due to invalid challenge"),
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
%% @doc 
%% @end
%%-------------------------------------------------------------------------
active_key(Dir, rsa)
    -> ok = active_key(key_path(Dir, "id_rsa.key"));
active_key(_, X)
    -> ct:pal(?_("active_key arg not found: ~p", [X])),
       exit(1).

active_key(File)
    -> Link = link_path(File),
       %ct:pal(?_("Making symlink ~p -> ~p", [File, Link])),
       case file:make_symlink(File, Link) of
            ok -> ok;
            {error, eexist} -> ok ;
            E -> E
       end.

%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
unactive_key(Dir, rsa)
    -> ok = unactive_key(key_path(Dir, "id_rsa.key"));
unactive_key(_, X)
    -> ct:pal(?_("unactive_key arg not found: ~p", [X])),
       exit(1).


unactive_key(FileOrLink)
    -> case  file:read_link(FileOrLink) of
              {error,_} -> unactive_key(link_path(FileOrLink)) ;
              {ok, _}   -> file:delete(FileOrLink)
       end.

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
    ok = application:set_env([{cipherl, Conf}]),
    {ok, _} = application:ensure_all_started(cipherl),
    % Add handler
    ok = gen_event:add_sup_handler(cipherl_event, cipherl_ct_sec_handler, []),
    gen_event:sync_notify(cipherl_event, {pid, self()}),
    ok.

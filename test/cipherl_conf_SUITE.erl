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
     Config.

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
 init_per_group(_GroupName, Config) ->
     Config.

 %%--------------------------------------------------------------------
 %% Function: end_per_group(GroupName, Config0) ->
 %%               term() | {save_config,Config1}
 %% GroupName = atom()
 %% Config0 = Config1 = [tuple()]
 %%--------------------------------------------------------------------
 end_per_group(_GroupName, _Config) ->
     ok.

 %%--------------------------------------------------------------------
 %% Function: init_per_testcase(TestCase, Config0) ->
 %%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
 %% TestCase = atom()
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %%--------------------------------------------------------------------
 init_per_testcase(_TestCase, Config) ->
     Config.

 %%--------------------------------------------------------------------
 %% Function: end_per_testcase(TestCase, Config0) ->
 %%               term() | {save_config,Config1} | {fail,Reason}
 %% TestCase = atom()
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %%--------------------------------------------------------------------
 end_per_testcase(_TestCase, _Config) ->
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
     ,{group, hidden_node}
     ,{group, mod_passphrase}
     ,{group, rpc_enabled}
     ,{group, security_handler}
     ,{group, system_dir}
     ,{group, ssh_dir}
     ,{group, ssh_pubkey_alg}
     ,{group, user_dir}
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
    TC.

 %%--------------------------------------------------------------------
 %% Function: TestCase(Config0) ->
 %%               ok | exit() | {skip,Reason} | {comment,Comment} |
 %%               {save_config,Config1} | {skip_and_save,Reason,Config1}
 %% Config0 = Config1 = [tuple()]
 %% Reason = term()
 %% Comment = term()
 %%--------------------------------------------------------------------
add_host_key_true_ok(_Config) ->  ok.
add_host_key_true_ko(_Config) ->  ok.
add_host_key_false_ok(_Config) ->  ok.
add_host_key_false_ko(_Config) ->  ok.
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
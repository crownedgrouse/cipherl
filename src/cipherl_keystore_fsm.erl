-module(cipherl_keystore_fsm).
-behaviour(gen_statem).

%% API.
-export([start_link/0]).

%% gen_statem.
-export([callback_mode/0]).
-export([init/1]).

-export([monitor_nodes/3]).

-export([handle_event/4]).
-export([terminate/3]).
-export([code_change/4]).

-export([check_auth/2]).


-export([format_status/2]).

-include("cipherl_records.hrl").

-include_lib("public_key/include/public_key.hrl").

-ifndef(debug).
    -define(INIT, erlang:process_flag(sensitive, true)).
-else.
    -define(INIT, logger:alert("!!! cipherl started in non safe 'debug' mode !!!")).
-endif.

% Digest used for message signing
-define(DIGEST, sha512).
%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
	gen_statem:start_link(?MODULE, [], []).

%% gen_statem.

callback_mode() ->
	state_functions.

format_status(Opt, [_PDict,_State,_Data]) ->
    case Opt of
    terminate ->
        hidden;
    normal ->
        hidden
    end.

%%-------------------------------------------------------------------------
%% @doc Init function
%% @end
%%-------------------------------------------------------------------------
init([]) ->
    ?INIT,
    erlang:register(cipherl_ks, self()),
    %erlang:process_flag(trap_exit, true),
    logger:info("Starting ~p", [?MODULE]),
    try 
        % Monitor nodes
        ok = net_kernel:monitor_nodes(true, [{node_type,all}]),
        logger:info("Monitoring all node types"),
        % Load config
        logger:info("Loading configuration"),
        Conf = load_config(),
        logger:debug("Config: ~p", [Conf]),
        % Is rpc enabled ?
        erlang:put(rpc_enabled, maps:get(rpc_enabled, Conf, false)),
        % Add mandatory security handler(s)
        % See [https://github.com/crownedgrouse/cipherl/wiki/1---Configuration#security_handler]
        logger:info("Adding mandatory security handler(s)"),
        SH = maps:get(security_handler, Conf),
        lists:foreach(fun(M) -> 
                        case gen_event:add_handler(cipherl_event, M, Conf) of
                            ok -> 
                                logger:notice("Mandatory handler added: ~p", [M]);
                            {_, Reason} -> 
                                logger:error("Mandatory handler addition failed: ~p", [M]),
                                logger:debug("Reason: ~p", [Reason]),
                                throw(mandatory_handler_missing)
                        end
                      end, SH),
        % Check security
        ok = check_security(Conf),
        logger:info("Security check: OK"),
        % Go on
        crypto:start(),
        % Get private key passphrase type and passphrase value
        Passphrase = get_passphrase(Conf),
        % Get ssh key type from config or id found on disk from passphrase type
        KT = maps:get(ssh_pubkey_alg, Conf, 'ssh-ecdsa-nistp521'),
        logger:debug("Private key type: ~p", [KT]),

        logger:info("Loading private key"),
        % Compose ssh_file function argument
        Userdir   = maps:get(user_dir, Conf, []),
        Systemdir = maps:get(system_dir, Conf, []),
        Args      = lists:flatten([Passphrase] ++ [Userdir] ++ [Systemdir]),
        % Define ssh_file target function
        Target = case maps:get(ssh_dir, Conf, 'user') of
                    system -> host_key;
                    user   -> user_key
                 end,
        % Get private key
        Private = 
            case ssh_file:Target(KT, Args) of
                {ok, Priv}      -> Priv;
                {error, Reason} -> 
                    logger:error("ssh_file:~p failure: ~p", [Target, Reason]),
                    throw("No private key found"), []
            end,
        % Unfortunately undocumented function !
        Public = ssh_transport:extract_public_key(Private),

        logger:notice("~p Init: OK", [?MODULE]),
	    {ok, monitor_nodes, #{nodes   => #{}
                             ,pending => #{}
                             ,private => Private
                             ,public  => Public
                             ,conf    => Conf
                             }
        }
    catch
        _:Msg -> exit(Msg)
    end.

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc Handle calls
%% @end
%%-------------------------------------------------------------------------
monitor_nodes({call, {From, Tag}}, {verify, Msg}, StateData) 
    when is_record(Msg, cipherl_msg)  ->
    {cipherl_msg, Node, P, S} = Msg,
    % Decrypt Payload
    Bin = public_key:decrypt_private(P, maps:get(private, StateData)), % TODO catch
    PubKey = get_pubkey_from_node(Node, StateData),
    case (catch public_key:verify(Bin, ?DIGEST, S, PubKey)) of
        true -> gen_statem:reply({From, Tag}, {ok, Node});
        X    -> logger:debug("~p", [X]),
                gen_statem:reply({From, Tag}, error)
    end,
    {next_state, monitor_nodes, StateData};
monitor_nodes({call, {From, Tag}}, {uncrypt, Msg}, StateData) 
    when is_record(Msg, cipherl_msg)  ->
    {cipherl_msg, _, P, _} = Msg,
    Bin = public_key:decrypt_private(P, maps:get(private, StateData)), % TODO catch
    gen_statem:reply({From, Tag}, Bin),
    {next_state, monitor_nodes, StateData};
monitor_nodes({call, {From, Tag}}, {crypt, Node, Msg, Pid}, StateData) ->
    try     
        % Check initial call
        check_initial_call(Node, process_info(Pid, initial_call), erlang:get(rpc_enabled), maps:get(pending, StateData)),
        % Get public key of Node
        PubKey = get_pubkey_from_node(Node, StateData),
        Bin = erlang:term_to_binary(Msg),
        % Crypt payload with recipient public key
        P=public_key:encrypt_public(Bin, PubKey),
        % Sign payload with local private key
        S=public_key:sign(Bin, ?DIGEST, maps:get(private, StateData)),
        % Compose cipherl_msg
        CM = #cipherl_msg{node=node(), payload=P, signed=S},
        gen_statem:reply({From, Tag}, CM)
    catch
        _:rpc_disabled ->
                ONode = case process_info(Pid, group_leader) of
                            {group_leader, N} -> N;
                            _ -> nonode@nohost
                        end,
                logger:warning("crypt call for ~p via rpc from ~p and destination ~p failed: rpc_disabled", [Pid, ONode, Node]),
                gen_event:notify(cipherl_event, {rpc_disabled, {Pid, ONode, Node}}),
                gen_statem:reply({From, Tag}, {cipherl_error, rpc_disabled});
        _:R ->  logger:warning("crypt call failed for ~p: ~p", [Pid, R]),
                gen_event:notify(cipherl_event, {rpc_disabled, {Pid, Node}}),
                gen_statem:reply({From, Tag}, {cipherl_error, R})
    end,
    {next_state, monitor_nodes, StateData};
monitor_nodes({call, {From, Tag}}, EventData, StateData) when is_pid(From)->
    logger:info("~p~p call received from ~p: ~p", [?MODULE, self(), {From, Tag}, EventData]),
    gen_statem:reply({From, Tag}, unexpected),
	{next_state, monitor_nodes, StateData};

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc Handle casts
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(cast, EventData, StateData) ->
    logger:info("~p~p cast received: ~p", [?MODULE, self(), EventData]),
    {next_state, monitor_nodes, StateData};

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc Node down event
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, {nodedown, Node, _}, StateData) ->
    % Remove node info in state
    Map1 = maps:remove(Node, maps:get(nodes, StateData)),
    Map2 = maps:remove(Node, maps:get(pending, StateData)),
    NewStateData = maps:merge(StateData, #{nodes => Map1, pending => Map2}),
    logger:notice("Removing node: ~p", [Node]),
    {next_state, monitor_nodes, NewStateData};
%%-------------------------------------------------------------------------
%% @doc Node up event
%%
%%    Hidden node can be discarded depending `hidden_node` value. 
%%    See [https://github.com/crownedgrouse/cipherl/wiki/1---Configuration#hidden_node]
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, {nodeup, Node, _}, StateData) ->
    try
        Conf = maps:get(conf, StateData),
        %% Fatal checks
        % Check hidden_node
        case lists:member(Node, erlang:nodes(hidden)) of
            true -> 
                case maps:get(hidden_node, Conf) of
                    false -> throw(hidden);
                    true  -> ok
                end;
            false -> ok
        end,
        % Check add_host_key
        case maps:get(add_host_key, Conf, false) of
            true  -> ok ;
            false -> 
                % Get hostname from Node
                 Host = get_host_from_node(Node),
                 % Check hostname is allowed
                 case is_hostname_allowed(Host, Conf) of
                      false -> throw(unauthorized_host);
                      true  -> ok
                 end
        end,

        %% OK we can go further
        Nonce = erlang:monotonic_time(),
        % Send authenfication challenge to Node
        {cipherl_ks, Node} ! hello_msg(StateData),
        % Start a timer for hello timeout 
        Time = case net_kernel:get_net_ticktime() of
                    ignore -> 5000 ;
                    {ongoing_change_to, NT} -> NT * 1000 ;
                    NT -> NT * 1000
               end,
        {ok, TRef} =  timer:send_after(Time, {hello_timeout, Node}),
        erlang:put(Node, TRef),
        logger:debug("Start timer - hello_timeout: ~p", [TRef]),
        % Add node as Pending with nonce expected
        Map1 = maps:merge(maps:get(pending, StateData),#{Node => Nonce}),
        NewStateData = maps:merge(StateData, #{pending => Map1}),
        logger:debug("Updating pending nodes : ~p",[Map1]),
        {next_state, monitor_nodes, NewStateData}
    catch
        _:unauthorized_host ->
                    rogue(Node),
                    gen_event:notify(cipherl_event, {unauthorized_host, Node}),
                    logger:warning("Rejecting node ~p : unauthorized host", [Node]),
                    {next_state, monitor_nodes, StateData};
        _:hidden -> rogue(Node),
                    gen_event:notify(cipherl_event, {unauthorized_hidden, Node}),
                    logger:warning("Rejecting hidden node ~p", [Node]),
                    {next_state, monitor_nodes, StateData};
        _:R:S    -> logger:error("Error: ~p", [R]),
                    logger:debug("Stacktrace: ~p", [S]),
                    {next_state, monitor_nodes, StateData}
    end;
%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, {hello_timeout, Node}, StateData) ->
    logger:warning("Hello timeout from node ~p", [Node]),
    Map1 = maps:remove(Node, maps:get(pending, StateData)),
    NewStateData = maps:merge(StateData, #{pending => Map1}),
    {next_state, monitor_nodes, NewStateData};
monitor_nodes(info, Msg, StateData) 
    when is_record(Msg, cipherl_auth) 
    ->
    Node = case (catch erlang:element(2, erlang:element(2, Msg))) of
                {'EXIT', _} -> 'unknown';
                X -> X
            end,
    try 
        % Check Node is a pending one
        case maps:is_key(Node, maps:get(pending, StateData)) of
            false -> logger:notice("Received auth message for not pending node ~p", [Node]);
            true  -> % Check it is a valid auth message
                     case check_auth(Msg, StateData) of
                        true  -> ok;
                        false -> throw(invalid_auth_msg)
                     end
        end,
        % Remove timeout
        timer:cancel(erlang:get(Node)),
        % Add node to authentified nodes and remove from pending
        Nonce = erlang:element(3, erlang:element(2, Msg)),
        Map1 = maps:put(Node, Nonce, maps:get(nodes, StateData)),
        Map2 = maps:remove(Node, maps:get(pending, StateData)),
        NewStateData = maps:merge(StateData, #{nodes => Map1, pending => Map2}),
        {next_state, monitor_nodes, NewStateData}
    catch
        _ -> 
             logger:error("Invalid auth message received from node: ~p", [Node]),
             logger:info("Msg: ~p", [Msg]),
             logger:notice("Disconnecting rogue node: ~p", [rogue(Node)]),
             {next_state, monitor_nodes, StateData}
    end;
monitor_nodes(info, EventData, StateData) ->
    logger:info("~p~p info received: ~p", [?MODULE, self(), EventData]),
    {next_state, monitor_nodes, StateData};
%%-------------------------------------------------------------------------
%% @doc Fallback
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(EventType, EventData, StateData) ->
    logger:warning("Unexpected message~nstate: monitor_nodes~nevent: ~p~ndata: ~p~n", [EventType, EventData]),
    {next_state, monitor_nodes, StateData}.

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
handle_event(EventType, EventData, StateName, StateData) ->
    logger:warning("Unexpected message~nstate: ~p~nevent: ~p~ndata: ~p~n", [StateName, EventType, EventData]),
	{next_state, StateName, StateData}.

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
terminate(Reason, _StateName, _StateData) ->
    net_kernel:monitor_nodes(false),
    logger:notice("~p terminating: ~p", [?MODULE, Reason]),
	ok.

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
code_change(_OldVsn, StateName, StateData, _Extra) ->
	{ok, StateName, StateData}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%  Local functions                                                    %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%-------------------------------------------------------------------------
%% @doc Forge a Hello message
%% @end
%%-------------------------------------------------------------------------
-spec hello_msg(#{}) -> tuple().

hello_msg(State) ->
    Hello = #cipherl_hello{
              node   = node()
            , nonce  = erlang:monotonic_time()
            , pubkey = maps:get(public, State)
            , algos  = ssh:default_algorithms()
            },
    Hello.

%%-------------------------------------------------------------------------
%% @doc Forge a Hello message
%% @end
%%-------------------------------------------------------------------------
-spec check_auth(tuple(), #{}) -> boolean().

check_auth(AuthMsg, State) 
    when  is_record(AuthMsg, cipherl_auth)
    ->
    try 
        {_, {cipherl_hello, Node, _, PubKey, Algos}, {cipherl_msg, Payload, Signed}} = AuthMsg,
        % Check node is a pending one, and get expected nonce
        Nonce =
        case maps:find(pending, State) of
            error         -> throw(no_pending_auth);
            {ok, Pending} ->
                case maps:find(Node, Pending) of
                    error -> throw(invalid_pending_node),
                             0;
                    {ok, N} -> N
                end
        end,
        % Check algos are compatible
        case cipherl_algos_fsm:compatible(Algos) of
            false -> throw(incompatible_algos);
            true  -> ok
        end,
        % Decrypt payload with my private key
        Bin  = public_key:decrypt_private(Payload, maps:get(private, State)),
        Data =
        case (catch erlang:binary_to_term(Bin, [safe])) of
            {'EXIT',{badarg,_ }} 
                 -> logger:debug(Bin),
                   throw(invalid_payload),
                   [];
            D when is_record(D, cipherl_chal)
                 -> D;
            D -> logger:debug(D),
                    throw(invalid_response),
                    []
        end,
        {cipherl_chal, ChalNode, ChalNonce, Random} = Data,
        % Check node is myself
        ChalNode = node(),
        % Check nonce was the one sent
        ChalNonce = Nonce,
        % Check random is not empty
        case lists:member(Random, [[],<<"">>, {}, #{}, 0]) of
            true   -> throw(invalid_empty_random);
            false  -> ok
        end,
        % Verify signature
        true = public_key:verify(Bin, ?DIGEST, Signed, PubKey) 
    catch
        C:E:S -> 
            logger:warning("Invalid auth message : ~p", [E]),
            logger:info("~p", [AuthMsg]),
            logger:debug("~p:~p:~p", [C, E, erlang:tl(S)]), % Remove function and argument from stacktrace. Private key must be always hidden
            false
    end;
check_auth(AuthMsg, _State) ->
    logger:warning("Invalid auth message record"),
    logger:debug("~p",[AuthMsg]),
    false.

%%-------------------------------------------------------------------------
%% @doc Disconnect a Rogue Node
%% @end
%%-------------------------------------------------------------------------
-spec rogue(any()) -> boolean().

rogue(Node) when is_atom(Node),(Node =/= node()) ->
    % Set an random cookie to this node
    erlang:set_cookie(Node, 
        erlang:list_to_atom(lists:flatten(io_lib:format("~p", 
        [erlang:phash2({erlang:monotonic_time(), rand:bytes(100)})])))),
    % Disconnect it
    erlang:disconnect_node(Node),
    gen_event:notify(cipherl_event, {rogue_node, Node}),
    true;
rogue(_) -> false.

%%-------------------------------------------------------------------------
%% @doc Get public Key of a node
%% @end
%%-------------------------------------------------------------------------
get_pubkey_from_node(Node, StateData) ->
    case Node of
        Node when (Node =:= node())
            -> maps:get(public, StateData) ;
        _   -> maps:get(public, StateData) % TODO
    end.

%%-------------------------------------------------------------------------
%% @doc Load config and set default
%% @end
%%-------------------------------------------------------------------------
-spec load_config() -> map().

load_config() ->
    Default = #{add_host_key => false
               ,hidden_node  => false
               ,local_node   => false
               ,rpc_enabled  => false
               ,security_handler => []
               ,ssh_dir      => user
               ,ssh_pubkey_alg => ''
               ,ssh_dir_override => false
               ,user_dir => []
               ,system_dir => []
               },
    % Find keys in config, and check validity
    Keys   = maps:keys(Default),
    Fun    = fun(K) -> case application:get_env(cipherl, K)  of
                            undefined -> [] ;
                            {ok, V} -> [check_conf_type(K, V)]
                       end
             end,
    New    = maps:from_list(lists:flatten(lists:flatmap(Fun, Keys))),
    Conf   = maps:merge(Default, New),
    Conf.

%%-------------------------------------------------------------------------
%% @doc Check type and possible values of config parameter
%% @end
%%-------------------------------------------------------------------------
-spec check_conf_type(atom(), any()) -> ok | tuple() | [] | no_return().

check_conf_type(K = add_host_key, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = hidden_node, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = local_node, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = rpc_enabled, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = security_handler, V) when is_list(V) 
    ->  {K, V};
check_conf_type(K = ssh_dir_override, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(_K = user_dir, V) when is_list(V),(V =:= [])
    -> [];
check_conf_type(K = user_dir, V) when is_list(V) 
    ->  {K, V};
check_conf_type(_K = system_dir, V) when is_list(V),(V =:= [])
    -> [];
check_conf_type(K = system_dir, V) when is_list(V) 
    ->  {K, V};
check_conf_type(K = ssh_pubkey_alg, V) when is_atom(V) 
    ->  L = ssh_pubkey_alg(),
        case lists:member(V, L) of
            false -> logger:warning("Invalid value for config parameter '~p': expected one of ~p, found ~p", [K, L, V]),
                     [];
            true  -> {K, V}
        end;
check_conf_type(K = ssh_dir, V) when is_atom(V) 
    ->  L = [system, user],
        case lists:member(V, L) of
            false -> logger:warning("Invalid value for config parameter '~p': expected one of ~p, found ~p", [K, L, V]),
                     [];
            true  -> {K, V}
        end;
check_conf_type(K, _) ->
        logger:warning("Invalid type for config parameter '~p'", [K]),
        [].


%%-------------------------------------------------------------------------
%% @doc Check security regarding config
%%      Events will be sent to handlers syncronously with a timeout before
%%      raising exception, in order to let handlers doing things.
%%-------------------------------------------------------------------------
-spec check_security(map()) -> ok | no_return().

check_security(Conf)   % TODO
    -> 
    % Verify that 'mod_passphrase' still unloaded after init
    PM = maps:get(mod_passphrase, Conf, ''),
    case code:is_loaded(PM) of
        false     -> ok;
        {file, _} -> logger:alert("Passphrase is unsafe : mod_passphrase ~p is loaded", [PM]),
                     Procs = get_proc_using_mod(PM),
                     remove_module(PM),
                     gen_event:notify(cipherl_event, {passphrase_unsafe, Procs}),
                     logger:notice("Processes using mod_passphrase: ~p", [Procs])
    end,
    % Verify conf did not changed at runtime
    CurConf = load_config(),
    case ( Conf =:= CurConf) of
        true  -> ok ;
        false -> Diff = maps:to_list(CurConf) -- maps:to_list(Conf), 
                 logger:warning("cipherl configuration changed since init: ~p", [Diff]),
                 gen_event:notify(cipherl_event, {config_change, Diff})
    end,
    % Verify mandatory handlers are still attached to gen_event
    % Verify all nodes are known
    % Verify all node are allowed
    ok.

%%-------------------------------------------------------------------------
%% @doc Allowed SSH pubkey algorithms
%%-------------------------------------------------------------------------
ssh_pubkey_alg()
    -> 
    case lists:keyfind(public_key, 1, ssh:default_algorithms()) of
         false -> logger:info("No public_key found in ssh:default_algorithms/0"),
                  [];
         {public_key, L} -> L       
    end.


%%-------------------------------------------------------------------------
%% @doc Get private key passphrase
%%-------------------------------------------------------------------------
-spec get_passphrase(map()) -> list() | no_return().

get_passphrase(Conf)
    when is_map(Conf)
    ->
    try 
        % Get mod_passphase
        MP = maps:get(mod_passphase, Conf, ''),
        case MP of
            '' -> "" ;
            _  -> 
            % Check abstract code is not available (either missing or crypted)

            % Check module is of cipherl_passphrase behavior

            % Get password for current node
            Passwd = MP:passwd(node()),
            case Passwd of
                {PT, _} -> logger:debug("Passphrase type : ~p", [PT]);
                _       -> ok
            end,
            % 
            ok = remove_module(MP),
            Passwd
        end
    catch
        _:_ -> 
            logger:error("Passphrase get failed"),
            throw(passphrase_failure)
    end. 

%%-------------------------------------------------------------------------
%% @doc Remove a module
%%-------------------------------------------------------------------------
-spec remove_module(atom()) -> ok | no_return().

remove_module(Module)
    ->
    try 
        % Find path to module file
        % BeamPath = 
        %     case code:is_loaded(Module) of
        %         {file, L} when is_list(L)
        %                   -> L;
        %         {file, _} -> "" ;
        %         false     -> ""
        %     end,
        % Unload module
        code:delete(Module),
        case code:soft_purge(Module) of
            true  -> ok ;
            false -> logger:notice("soft purge of '~p' failed due to some process using old code", [Module]),
                     true = code:purge(Module),
                     logger:notice("purge of '~p' was forced")
        end
        % % Remove beam file on disk
        % case BeamPath of
        %     "" -> ok ;
        %     P -> case file:delete(P, [raw]) of
        %             {error, R} -> logger:notice("Could not delete file '~p' on disk : ~p", [P,R]),
        %                           throw(delete_failed);
        %             ok -> ok
        %          end
        % end
    catch
        _:_ -> 
            logger:error("Module removing failed : ~p", [Module]),
            throw(unremoved_module)
    end.

%%-------------------------------------------------------------------------
%% @doc Check compatibilty of types of key and passphrase
%%-------------------------------------------------------------------------
% TODO
%check_types(_KT, _PT) -> ok. 


%%-------------------------------------------------------------------------
%% @doc Get host from node name
%%-------------------------------------------------------------------------
-spec get_host_from_node(node()) -> string().

get_host_from_node(Node)
    ->
    case string:split(erlang:atom_to_list(Node), "@") of
        [_,H] -> H;
        _     -> "nohost"
    end.

%%-------------------------------------------------------------------------
%% @doc Check Host is already known in know_hosts
%%      This is only a first check at hostname, not fingerprint
%%-------------------------------------------------------------------------
is_hostname_allowed(Host, Conf)
    ->
    File =
    case maps:get(ssh_dir, Conf) of
        system -> Dir = maps:get(system_dir, Conf),
                  filename:join(Dir, "ssh_known_hosts");
        user   -> Dir = maps:get(user_dir, Conf),
                  filename:join(Dir, "known_hosts")
    end,
    L = decode_known_hosts(File),
    logger:debug("known_hosts: ~p", [L]),
    % Get hostnames
    Hosts = get_from_known_hosts(hosts, L),
    lists:member(Host, Hosts).

%%-------------------------------------------------------------------------
%% @doc Extract things from known_hosts
%% [{ssh2,[<<"hostname">>,
%%         <<"ecdsa-sha2-nistp521">>,
%%         <<"AAAAE2VjZHNhL ... xMdMCuapbOg==">>]}]
%%
%%      @note For now only 'hosts' argument implemented
%%-------------------------------------------------------------------------
get_from_known_hosts(hosts, L)
    ->
    lists:flatmap(fun({_, X}) -> [binary_to_list(lists:nth(1, X))] end, L).

%%-------------------------------------------------------------------------
%% @doc Decode known hosts file
%%-------------------------------------------------------------------------
decode_known_hosts(File)
    ->
    try 
        % Check file exists 
        case filelib:is_regular(File) of
            true -> ok;
            false -> throw("Not found")
        end,
        % Read file 
        Bin = 
        case file:read_file(File) of
            {ok, B} -> B;
            {error, Reason} -> throw(Reason), <<"">>
        end,
        % Split file line by line
        Lines = binary:split(Bin, list_to_binary(io_lib:nl()), [trim_all]),
        lists:flatmap(fun(Line) -> [decode_known_hosts_line(Line)] end, Lines)
    catch
        _:R -> logger:error("Error while decoding ~p : ~p", [File, R]),
               []
    end.

%%-------------------------------------------------------------------------
%% @doc Decode known hosts file entry (line)
%%-------------------------------------------------------------------------
decode_known_hosts_line(Line) ->
    [First, Rest] = binary:split(Line, <<" ">>, []),
    [Second, Rest1] = binary:split(Rest, <<" ">>, []),

    case is_bits_field(Second) of
        true ->
            {ssh1, decode_known_hosts_ssh1(First, Second, Rest1)};
        false ->
            {ssh2, decode_known_hosts_ssh2(First, Second, Rest1)}
    end.

%%-------------------------------------------------------------------------
%% @doc Decode known_hosts in ssh1 format
%%-------------------------------------------------------------------------
decode_known_hosts_ssh1(Hostnames, Bits, Rest) ->
    [Hostnames, Bits | split_n(2, Rest,  [])].

%%-------------------------------------------------------------------------
%% @doc Decode known_hosts in ssh2 format
%%-------------------------------------------------------------------------
decode_known_hosts_ssh2(Hostnames, KeyType, Rest) ->
    [Hostnames, KeyType | split_n(1, Rest,  [])].

%%-------------------------------------------------------------------------
%% @doc Split binary
%%-------------------------------------------------------------------------
split_n(0, <<>>, Acc) ->
    lists:reverse(Acc);
split_n(0, Bin, Acc) ->
    lists:reverse([Bin | Acc]);
split_n(N, Bin, Acc) ->
    case binary:split(Bin, <<" ">>, []) of
        [First, Rest] ->
            split_n(N-1, Rest, [First | Acc]);
        [Last] ->
            split_n(0, <<>>, [Last | Acc])
    end.

%%-------------------------------------------------------------------------
%% @doc Test if a known_hosts field are bits
%%-------------------------------------------------------------------------
is_bits_field(Part) ->
    try list_to_integer(binary_to_list(Part)) of
        _ ->
            true
    catch _:_ ->
            false
    end.

%%-------------------------------------------------------------------------
%% @doc Get processes using a module
%%      Mainly for detection of processes using passphrase module
%%-------------------------------------------------------------------------
-spec get_proc_using_mod(atom()) -> list().

get_proc_using_mod(Module) when is_atom(Module) ->
    Fun = fun(X) -> 
            case (X =:= self()) of
                true -> ok;
                false -> 
                    case (catch sys:get_status(X, 100)) of
                        {status, Pid,{module, Module}, _} -> [Pid] ;
                        _  -> []
                    end
             end
        end,
    lists:flatmap(Fun, elang:processes()).

%%-------------------------------------------------------------------------
%% @doc Check initial call is allowed
%%-------------------------------------------------------------------------
-spec check_initial_call(atom(), tuple(), boolean(), map()) -> ok | no_return().

check_initial_call(Node, IC, RPC, Pendings) 
    when is_atom(Node),is_tuple(IC),is_boolean(RPC),is_map(Pendings) ->
    {initial_call, {M, _F, _A}} = IC,
    case lists:member(M, [rpc, erpc]) of
        false -> ok ;
        true  when (RPC =:= true) ->
            % Check Node is not pending
            case maps:is_key(Node, Pendings) of
                false -> ok ;
                true  -> throw(rpc_disabled)
            end;
        _  -> throw(rpc_disabled)
    end;
check_initial_call(_, _, _, _) ->
    throw(rpc_disabled).
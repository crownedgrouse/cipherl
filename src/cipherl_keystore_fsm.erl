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
        logger:info("Loading private key"),
        Private = 
            case ssh_file:user_key('ssh-rsa', []) of
                {ok, Priv}      -> Priv;
                {error, Reason} -> 
                    logger:error("ssh_file:user_key failure: ~p", [Reason]),
                    throw("No private user key found"), []
            end,
        MO = erlang:element(3, Private),
        PE = erlang:element(4, Private),
        Public  = #'RSAPublicKey'{modulus=MO, publicExponent=PE},

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
    case (catch public_key:verify(Bin, sha256, S, PubKey)) of
        true -> gen_statem:reply({From, Tag}, {ok, Node});
        X    -> logger:debug("~p", [X]),
                gen_statem:reply({From, Tag}, error)
    end,
    {next_state, monitor_nodes, StateData};
monitor_nodes({call, {From, Tag}}, {crypt, Node, Msg}, StateData) ->
    % Get public key of Node
    PubKey = get_pubkey_from_node(Node, StateData),
    Bin = erlang:term_to_binary(Msg),
    % Crypt payload with recipient public key
    P=public_key:encrypt_public(Bin, PubKey),
    % Sign payload with local private key
    S=public_key:sign(Bin, sha256, maps:get(private, StateData)),
    %
    CM = #cipherl_msg{node=node(), payload=P, signed=S},
    gen_statem:reply({From, Tag}, CM),
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
    logger:info("Removing node: ~p", [Node]),
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
        case lists:member(Node, erlang:nodes(hidden)) of
            true -> case maps:get(hidden_node, Conf) of
                        false -> throw(hidden);
                        true  -> ok
                    end;
            false -> ok
        end,
        Nonce = erlang:monotonic_time(),
        % Send authenfication challenge to Noded
        {cipherl_ks, Node} ! hello_msg(StateData),
        % Start a timer for hello timeout 
        Time = case net_kernel:get_net_ticktime() of
                    ignore -> 5000 ;
                    {ongoing_change_to, NT} -> NT * 1000 ;
                    NT -> NT * 1000
               end,
        {ok, TRef} =  timer:send_after(Time, {hello_timeout, Node}),
        erlang:put(Node, TRef),
        logger:info("Start timer - hello_timeout: ~p", [TRef]),
        % Add node as Pending with nonce expected
        Map1 = maps:merge(maps:get(pending, StateData),#{Node => Nonce}),
        NewStateData = maps:merge(StateData, #{pending => Map1}),
        logger:debug("Updating pending nodes : ~p",[Map1]),
        {next_state, monitor_nodes, NewStateData}
    catch
        _:hidden -> rogue(Node),
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
terminate(_Reason, _StateName, _StateData) ->
    net_kernel:monitor_nodes(false),
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
        true = public_key:verify(Bin, sha256, Signed, PubKey) % TODO hash choice
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
    erlang:disconnect_node(Node);
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
               ,security_handler => []
               ,ssh_dir      => any
               ,ssh_sysdir_override => false
               ,ssh_userdir_override => false
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
check_conf_type(K = add_host_key, _V)  
    ->  logger:warning("Invalid type for config parameter '~p'", [K]),
        [];
check_conf_type(K = hidden_node, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = hidden_node, _V)  
    ->  logger:warning("Invalid type for config parameter '~p'", [K]),
        [];
check_conf_type(K = local_node, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = local_node, _V)  
    ->  logger:warning("Invalid type for config parameter '~p'", [K]),
        [];
check_conf_type(K = security_handler, V) when is_list(V) 
    ->  {K, V};
check_conf_type(K = security_handler, _V)  
    ->  logger:warning("Invalid type for config parameter '~p'", [K]),
        [];
check_conf_type(K = ssh_sysdir_override, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = ssh_sysdir_override, _V)  
    ->  logger:warning("Invalid type for config parameter '~p'", [K]),
        [];
check_conf_type(K = ssh_userdir_override, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = ssh_userdir_override, _V)  
    ->  logger:warning("Invalid type for config parameter '~p'", [K]),
        [];
check_conf_type(K = ssh_dir, V) when is_atom(V) 
    ->  L = [any, sys, user],
        case lists:member(V, L) of
            false -> logger:warning("Invalid value for config parameter '~p': expected one of ~p, found ~p", [K, L, V]),
                     [];
            true  -> {K, V}
        end;
check_conf_type(K = ssh_dir, _V)  
    ->  logger:warning("Invalid type for config parameter '~p'", [K]),
        [];
% Note: should never go here as load_config/0 do not care of invalid config parameter
check_conf_type(K, _) ->
    logger:error("Unknown config parameter: '~p'", [K]),
    throw(invalid_config).


%%-------------------------------------------------------------------------
%% @doc Check security regarding config
%%      Events will be sent to handlers syncronously with a timeout before
%%      raising exception, in order to let handlers doing things.
%%-------------------------------------------------------------------------
-spec check_security(map()) -> ok | no_return().

check_security(_Conf)   % TODO
    -> 
    % Verify conf did not changed at runtime
    % Verify all nodes are known
    % Verify all node are allowed
    % Verify ssh config

    ok.
%%%-------------------------------------------------------------------
%%% File:      cipherl_keystore_fsm.erl
%%% @author    Eric Pailleau <cipherl@crownedgrouse.com>
%%% @copyright 2022 crownedgrouse.com
%%% @doc
%%% Cipherl keystore finite state machine
%%% @end
%%%
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

-export([check_auth/2, check_security/1, check_security/2]).


-export([format_status/1]).

-include("cipherl_records.hrl").

-include_lib("public_key/include/public_key.hrl").

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

-ifndef(debug).
    -define(INITD, erlang:process_flag(sensitive, true)).
-else.
    -define(INITD, logger:alert("!!! cipherl started in non safe 'debug' mode !!!")).
-endif.

% Digest used for message signing
-define(DIGEST, sha512).

% 
-ifdef(TEST).
    % Do not really disconnect node for common tests, to allow clean peer:stop/1 .
    -define(DISCONNECT(Node),logger:info("cipherl would have disconnect node ~p", [Node])).
    -warning("Compiling specially for common tests. Do not use in production.").
    -define(INITT,
        put(test, true),
        case whereis(ct_util_server) of
            undefined -> 
                logger:warning("!!! Compiled for common tests. Do not use in production.");
            _ -> ok
        end
        ).
-else.
    % Disconnect it
    -define(DISCONNECT(Node),
        erlang:display(erlang:disconnect_node(Node)),
        erlang:set_cookie(Node, 
            erlang:list_to_atom(lists:flatten(io_lib:format("~p", 
            [erlang:phash2({erlang:monotonic_time(), rand:bytes(100)})]))))).
    -define(INITT,ok).
-endif.
%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
	gen_statem:start_link(?MODULE, [], []).

%% gen_statem.

callback_mode() ->
	state_functions.

format_status(Opt) ->
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
init(_) ->
    ?INITD,
    ?INITT,
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
        case check_security(Conf, true) of
            ok    -> logger:info("Security check: OK");
            error -> erlang:error("Security reason")
        end,
        % Go on
        crypto:start(),

        % Get ssh key type from config 
        KT = maps:get(ssh_pubkey_alg, Conf, 'ssh-ecdsa-nistp521'),
        logger:debug("Private key type: ~p", [KT]),

        % Get private key passphrase type and passphrase value
        Passphrase = get_passphrase(KT, Conf),

        logger:info("Loading private key"),
        % Compose ssh_file function argument
        Userdir   = maps:get(user_dir, Conf, []),
        Systemdir = maps:get(system_dir, Conf, []),
        Args      = lists:flatten([{ecdsa_pass_phrase,Passphrase}] ++ [{user_dir, Userdir}] ++ [Systemdir]),
        logger:debug("Args: ~p", [Args]),
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
                    logger:error("ssh_file:~p failure: ~p directory:~p", [Target, Reason, Userdir]),
                    logger:notice("key_type:~p  args:~p",[KT, Args]),
                    throw("No private key found"), []
            end,
        Public = ?PUBKEY(Private),

        case global:register_name({cipherl_ks, node()}, self()) of
            yes -> ok;
            no  ->  logger:notice("registered name at node ~p already set", [node()]),
                    global:re_register_name({cipherl_ks, node()}, self())
        end,
        case get(test) of
            true -> ok ;
            _ -> logger:notice("~p Init: OK", [?MODULE])
        end,
	    {ok, monitor_nodes, #{nodes   => #{}
                             ,pending => #{}
                             ,private => Private
                             ,public  => Public
                             ,conf    => Conf
                             }
        }
    catch
        _:Msg:Stack -> 
            logger:error("Error : ~p~n~p", [Msg,Stack]),
            exit(Msg)
    end.

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc Handle calls
%% @end
%%-------------------------------------------------------------------------
monitor_nodes({call, {From, Tag}}, {verify, Msg}=PL, StateData) 
    when is_record(Msg, cipherl_msg)  ->
    {cipherl_msg, Node, P, S} = Msg,
    logger:info("~p~p cast received from ~p: ~p while in state ~p", [?MODULE, self(), {From, Tag}, PL, hide_sensitive(StateData)]),
    % Decrypt Payload
    Bin = public_key:decrypt_private(P, maps:get(private, StateData)), % TODO catch
    PubKey = get_pubkey_from_node(Node, StateData),
    case (catch public_key:verify(Bin, ?DIGEST, S, PubKey)) of
        true -> gen_statem:reply({From, Tag}, {ok, Node});
        X    -> logger:debug("~p", [X]),
                gen_statem:reply({From, Tag}, error)
    end,
    {next_state, monitor_nodes, StateData};
monitor_nodes({call, {From, Tag}}, {uncrypt, Msg}=PL, StateData) 
    when is_record(Msg, cipherl_msg)  ->
    {cipherl_msg, _, P, _} = Msg,
    logger:info("~p~p cast received from ~p: ~p while in state ~p", [?MODULE, self(), {From, Tag}, PL, hide_sensitive(StateData)]),
    Bin = public_key:decrypt_private(P, maps:get(private, StateData)), % TODO catch
    gen_statem:reply({From, Tag}, Bin),
    {next_state, monitor_nodes, StateData};
monitor_nodes({call, {From, Tag}}, {crypt, Node, Msg, Pid} = PL, StateData) ->
    logger:info("~p~p cast received from ~p: ~p while in state ~p", [?MODULE, self(), {From, Tag}, PL, hide_sensitive(StateData)]),
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
    logger:info("~p~p event received from ~p: ~p while in state ~p", [?MODULE, self(), Node, nodedown, hide_sensitive(StateData)]),
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
    logger:info("~p~p event received from ~p: ~p while in state ~p", [?MODULE, self(), Node, nodeup, hide_sensitive(StateData)]),
    % Get hostname from Node
    Host = get_host_from_node(Node),
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
                 % Check hostname is allowed
                 case is_hostname_allowed(Host, Conf) of
                      false -> erlang:display("*********** ICI ************"),
                        throw(unauthorized_host);
                      true  -> logger:info("Host ~p was found in 'know_hosts'", [Host]),
                               gen_event:notify(cipherl_event, {authorized_host, Host}),
                               ok
                 end
        end,
        %% OK we can go further
        Attempts = maps:get(attempt, Conf),
        Time = get_timer(),
        % Do attempt - 1 check until timeout
        A = case (Attempts > 1) of 
                false -> 1;
                true  -> Attempts - 1
            end,
        DTime = round(Time / A),
        logger:info("Configuring ~p ms timer (~p attempts) for node ~p", [Time, Attempts, Node]),
        {ok, TRef} =  timer:send_after(DTime, {node_timeout, Node, (A - 1), DTime}),
        erlang:put(Node, TRef),
        logger:debug("Start ~p ms timer (remaining attempts #~p) for ~p - node_timeout: ~p", [DTime, A, Node, TRef]),
        {next_state, monitor_nodes, StateData}
    catch
        _:unauthorized_host ->
                    rogue(Node),
                    gen_event:notify(cipherl_event, {unauthorized_host, Host}),
                    logger:warning("Rejecting node ~p : unauthorized host ~p", [Node, Host]),
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
%% @doc Receive node timeout while connected but remote cîpherl wasn't found so far
%% @end
%%-------------------------------------------------------------------------

monitor_nodes(info, {node_timeout, Node, Remain, DTime}, StateData) when (Remain > 0)->
    global:sync(),
    case global:whereis_name({cipherl_ks, Node}) of
        undefined 
            ->  
            net_adm:ping(Node),
            % Start a timer for node timeout 
            {ok, TRef} =  timer:send_after(DTime, {node_timeout, Node, (Remain - 1), DTime}),
            erlang:put(Node, TRef),
            logger:debug("Start ~p ms timer (remaining attempts #~p) for ~p - node_timeout: ~p", [DTime, Remain, Node, TRef]);
        _   -> % cipherl exists at remote side (fake a final timeout)
            self() ! {node_timeout, Node, 0, DTime},
            ok 
    end,
    {next_state, monitor_nodes, StateData};
monitor_nodes(info, {node_timeout, Node, 0, _}, StateData) ->
    logger:info("~p~p event received from ~p: ~p while in state ~p", [?MODULE, self(), Node, node_timeout, hide_sensitive(StateData)]),
    Conf = maps:get(conf, StateData),
    TM = maps:get(trust_mode, Conf),
    %% sync before a last (or a forced) attempt
    global:sync(),
    case global:whereis_name({cipherl_ks, Node}) of
        undefined -> 
            logger:info("cipherl still not found in global registry for ~p", [Node]),
            case TM of
                1 -> logger:warning("Unauthenticated node ~p allowed to connect (trust_mode=~p)", [Node, TM]);
                _ -> rogue(Node),
                     logger:notice("~p~p Disconnecting rogue node (trust_mode=~p): ~p", [?MODULE, self(), TM, Node])
            end,
            {next_state, monitor_nodes, StateData};
        Pid when is_pid(Pid) -> 
            % Affect a Nonce to Bob
            Nonce = erlang:monotonic_time(),
            % Send authenfication challenge to Node BoB
            logger:notice("Sending hello_msg to node ~p", [Node]),
            erlang:send(Pid, hello_msg(StateData, Nonce)),
            % Start a timer for hello timeout 
            Time = get_timer(),
            {ok, TRef} =  timer:send_after(Time, {hello_timeout, Node}),
            erlang:put({timer, Node}, TRef),
            logger:debug("Start ~p ms timer - hello_timeout: ~p", [Time, TRef]),
            % Add node as Pending with nonce expected
            Map1 = maps:merge(maps:get(pending, StateData),#{Node => Nonce}),
            NewStateData = maps:merge(StateData, #{pending => Map1}),
            logger:warning("~p Updating pending nodes : ~p",[node(), Map1]),
            {next_state, monitor_nodes, NewStateData}
    end;
%%-------------------------------------------------------------------------
%% @doc Receive hello timeout while challenge is running
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, {hello_timeout, Node}, StateData) ->
    logger:info("~p~p event received from ~p: ~p while in state ~p", [?MODULE, self(), Node, hello_timeout, hide_sensitive(StateData)]),
    Conf = maps:get(conf, StateData),
    TM = maps:get(trust_mode, Conf),
    logger:warning("Hello timeout for node ~p", [Node]),
    Map1 = maps:remove(Node, maps:get(pending, StateData)),
    NewStateData = maps:merge(StateData, #{pending => Map1}),
    logger:notice("Removing node ~p from pending", [Node]),
    case TM of
        1 -> logger:warning("Unauthenticated node ~p allowed to connect", [Node]);
        _ -> rogue(Node)
    end,
    gen_event:notify(cipherl_event, {hello_timeout, Node}),
    {next_state, monitor_nodes, NewStateData};
%%-------------------------------------------------------------------------
%% @doc Treat auth message
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, Msg, StateData) 
    when is_record(Msg, cipherl_auth) 
    ->
    Conf = maps:get(conf, StateData),
    {cipherl_auth, BobNode, BobNonce, BobPubKey, _Payload, _Signed} = Msg,
    try 
        % Remove timeout
        catch (timer:cancel(erlang:get({timer, BobNode}))),

        % Check Node is a pending one
        case maps:is_key(BobNode, maps:get(pending, StateData)) of
            false -> throw(unexpected_auth_msg) ;
            true  -> % Check it is a valid auth message
                     case check_auth(Msg, StateData) of
                        true  -> ok;
                        false -> throw(invalid_auth_msg)
                     end
        end,
        % Add host is required
        case maps:get(add_host_key, Conf, false) of
            false  -> ok ;
            true -> 
                % Get hostname from Node
                Host = get_host_from_node(BobNode),
                %
                Port = 4369, % Empd port TODO
                PubKey  = case erlang:get({pubkey, BobNode}) of
                            undefined -> erlang:put({pubkey, BobNode}, BobPubKey),
                                         BobPubKey;
                            X when (X =:= BobPubKey)-> X ;
                            _  -> % TODO decide if a security issue
                                  BobPubKey
                       end,
                % set user_dir
                UD = case maps:get(user_dir, Conf) of
                         [] -> [];
                         D  -> {user_dir, D}
                     end,
                KT = maps:get(ssh_pubkey_alg, Conf, 'ssh-ecdsa-nistp521'),
                Options = lists:flatten([UD]),
                % Check if already existing before adding
                F = ssh_file:is_host_key(PubKey, Host, Port, KT, Options),
                case F of
                    true -> 
                        logger:notice("~p : Host already existing in known_hosts (~p, ~p, ~p). Skipping.", [BobNode, Host, Port, KT]);
                    false -> 
                        case ssh_file:add_host_key(Host, Port, PubKey, Options) of
                            ok -> gen_event:notify(cipherl_event, {authorized_host, Host}),
                                  ok;
                            {error, T} -> 
                                logger:debug({error, T}),
                                throw(add_host_key_failure)
                        end
                end                
        end,
        % Add node to authenticated nodes and remove from pending
        Map1 = maps:put(BobNode, BobNonce, maps:get(nodes, StateData)),
        Map2 = maps:remove(BobNode, maps:get(pending, StateData)),
        NewStateData = maps:merge(StateData, #{nodes => Map1, pending => Map2}),
        % Sent event and log
        gen_event:notify(cipherl_event, {authenticated_node, BobNode}),
        logger:notice("node ~p was authenticated", [BobNode]),
        {next_state, monitor_nodes, NewStateData}
    catch
        _:add_host_key_failure -> 
             gen_event:notify(cipherl_event, {unauthenticated_node, BobNode}),
             logger:error("~p~p Failure while adding host key for node: ~p", [?MODULE, self(), BobNode]);
        _:unexpected_auth_msg  -> 
             logger:notice("~p~p Received auth message for not pending node: ~p", [?MODULE, self(), BobNode]),
             {next_state, monitor_nodes, StateData};
        _:invalid_auth_msg -> 
             logger:error("~p~p Invalid auth message received from node: ~p", [?MODULE, self(), BobNode]),
             logger:info("Msg: ~p", [Msg]),
             logger:notice("~p~p Disconnecting rogue node: ~p", [?MODULE, self(), rogue(BobNode)]),
             {next_state, monitor_nodes, StateData}
    end;
%%-------------------------------------------------------------------------
%% @doc Treat Hello message : send back a Auth message
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, Msg, StateData) 
    when is_record(Msg, cipherl_hello) ->
    %erlang:display(Msg),
    BobNode   = Msg#cipherl_hello.node,
    BobNonce  = Msg#cipherl_hello.nonce,
    BobPubKey = Msg#cipherl_hello.pubkey,
    _Algos  = Msg#cipherl_hello.algos,
    % Check Algos are compatible TODO
    % Send back Auth message
    case global:whereis_name({cipherl_ks, BobNode}) of
        undefined -> 
            logger:info("cipherl is not found in global registry for ~p: aborting auth message sending", [BobNode]),
            {next_state, monitor_nodes, StateData};
        Pid when is_pid(Pid) ->
            erlang:put({pubkey, BobNode}, BobPubKey), % Temporary store pubkey of node, until recorded in authorized key after auth.
            AliceNonce = erlang:monotonic_time(),
            AlicePubKey = maps:get(public, StateData),
            erlang:put({nonce, BobNode}, AliceNonce), % Affect a nonce to Bob node
            % Create challenge response
            Bin = erlang:term_to_binary({cipherl_chal, BobNode, BobNonce, AliceNonce, rand:bytes(10)}),
            % Crypt payload with recipient public key
            P=public_key:encrypt_public(Bin, BobPubKey),
            % Sign payload with local private key
            S=public_key:sign(Bin, ?DIGEST, maps:get(private, StateData)),
            % Compose and send cipherl_auth
            erlang:send(Pid, {cipherl_auth, 
                              node(), 
                              AliceNonce,
                              AlicePubKey,
                              P,
                              S
                              }),
            logger:info("sending auth message to ~p", [BobNode]),
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
    gen_event:notify(cipherl_event, {cipherl_stopped, {?MODULE, Reason}}),
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
-spec hello_msg(#{}, integer()) -> tuple().

hello_msg(State, Nonce) ->
    Hello = #cipherl_hello{
              node   = node()
            , nonce  = Nonce
            , pubkey = maps:get(public, State)
            , algos  = ssh:default_algorithms()
            },
    Hello.

%%-------------------------------------------------------------------------
%% @doc Check a auth message
%% @end
%%-------------------------------------------------------------------------
-spec check_auth(tuple(), #{}) -> boolean().

check_auth(AuthMsg, State) 
    when  is_record(AuthMsg, cipherl_auth)
    ->
    {cipherl_auth, BobNode, BobNonce, BobPubKey, Payload, Signed} = AuthMsg,
    try 
        % Check node is a pending one, and get expected nonce
        logger:info("Treating auth message from ~p", [BobNode]),
        Nonce = case maps:find(pending, State) of
                    error -> 
                        logger:debug("~p : No pending node(s)", [BobNode]),
                        throw(no_pending_auth);
                    {ok, Pending} ->
                        case maps:find(BobNode, Pending) of
                            error -> 
                                logger:debug("~p : Node was NOT pending", [BobNode]),
                                throw(not_pending_node),
                                0;
                            {ok, N} -> 
                                logger:debug("~p : Node was pending", [BobNode]),
                                N
                        end
                end,
        
        % Check algos are compatible
        %case cipherl_algos_fsm:compatible(Algos) of
        %    false -> throw(incompatible_algos);
        %    true  -> ok
        %end,
        % Decrypt payload with my private key
        Bin  = public_key:decrypt_private(Payload, maps:get(private, State)),
        logger:debug("~p : Challenge payload was decrypted with success", [BobNode]),
        Data =  case (catch erlang:binary_to_term(Bin, [safe])) of
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
        logger:debug("~p : Challenge term is a valid cipherl_chal record", [BobNode]),
        {cipherl_chal, HelloNode, HelloNonce, BobNonce2, Random} = Data,
        % Check node is myself
        case (HelloNode =:= node()) of
            true  -> logger:debug("~p : Node in challenge is current node", [BobNode]) ;
            false -> logger:warning("~p : Node in challenge is NOT current node", [BobNode]),
                     throw(invalid_challenge)
        end,
        % Check nonce was the one sent
        case (HelloNonce =:= Nonce) of 
            true  -> logger:debug("~p : Nonce in challenge is expected one", [BobNode]) ;
            false -> logger:warning("~p : Nonce in challenge is NOT the expected one (~p =/= ~p)", [BobNode, Nonce, HelloNonce]),
                     throw(invalid_challenge)
        end,
        % Check both Bob Nonce are the same
        case (BobNonce =:= BobNonce2) of 
            true  -> logger:debug("~p : Nonce in challenge is same than clear Nonce in auth message", [BobNode]) ;
            false -> logger:warning("~p : Nonce in challenge is NOT the same than clear one (~p =/= ~p)", [BobNode, BobNonce, BobNonce2]),
                     throw(invalid_challenge)
        end,
        % Check random is not empty
        case lists:member(Random, [[],<<"">>, {}, #{}, 0]) of
            true   -> throw(invalid_empty_random);
            false  -> ok
        end,
        logger:debug("~p : Random value in challenge is not empty", [BobNode]),
        PubKey = case erlang:get({pubkey, BobNode}) of 
                    undefined ->
                        logger:debug("~p : Pubkey was not known before, using it", [BobNode]),
                        BobPubKey ;
                    X when (X =:= BobPubKey) -> 
                        logger:debug("~p : Pubkey was known and is the same in challenge", [BobNode]),
                        X ;
                    X -> % Decide later if it is a security issue
                        logger:warning("~p : Pubkey in challenge is NOT the same than already known", [BobNode]),
                        X
                 end,
        logger:debug("~p : verifying signature of payload", [BobNode]),
        % Verify signature
        true = public_key:verify(Bin, ?DIGEST, Signed, PubKey) 
    catch
        _:not_pending_node ->
            case maps:is_key(BobNode, maps:get(nodes, State)) of
                true  -> logger:info("~p : already authenticated", [BobNode]);
                false -> logger:notice("~p : not pending and not known", [BobNode])
            end,
            true;
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
    erlang:display(erlang:disconnect_node(Node)),
    % Set an random cookie to this node
    ?DISCONNECT(node),
    gen_event:notify(cipherl_event, {rogue_node, Node}),
    true;
rogue(_) -> 
    erlang:display(rogue_on_invalid_node),
    false.

%%-------------------------------------------------------------------------
%% @doc Get public Key of a node
%% @end
%%-------------------------------------------------------------------------
get_pubkey_from_node(Node, StateData)
     ->
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
    Default = #{add_host_key      => false
               ,attempt           => 10
               ,check_rs          => true
               ,hidden_node       => false
               ,local_node        => false
               ,nonce_tolerance   => 0
               ,nonce_sched_id    => false
               ,rpc_enabled       => false
               ,security_handler  => []
               ,ssh_dir           => user
               ,user_dir          => []
               ,system_dir        => []
               ,ssh_pubkey_alg    => 'ssh-ecdsa-nistp521'
               ,trust_mode        => 0
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
check_conf_type(K = nonce_sched_id, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = nonce_tolerance, V) when is_integer(V),(V >= 0)
    ->  {K, V};
check_conf_type(K = check_rs, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = rpc_enabled, V) when is_boolean(V) 
    ->  {K, V};
check_conf_type(K = security_handler, V) when is_list(V) 
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
check_conf_type(K, _X) ->
        logger:warning("Invalid type for config parameter '~p', received: ~p", [K, _X]),
        [].


%%-------------------------------------------------------------------------
%% @doc Check security regarding config
%%      Events will be sent to handlers syncronously with a timeout before
%%      raising exception, in order to let handlers doing things.
%%      Mode=true More verbose, mainly for first check at init
%%      Mode=false Less verbose (default)
%%-------------------------------------------------------------------------
-spec check_security(map()) -> ok | error.

check_security(Conf) -> check_security(Conf, false).

-spec check_security(map(), boolean()) -> ok | error.

check_security(Conf, Mode)   % TODO
    -> 
    try 
        % Verify restricted shell security
        CRS = case application:get_env(cipherl,check_rs) of
                {ok, RS} when is_boolean(RS) -> RS ;
                _ -> true
              end,
        case application:get_env(stdlib, restricted_shell) of
            {ok, RSM} when (CRS =:= true)  ->  
                % Check RSM is a valid module
                case  code:ensure_loaded(RSM) of 
                    {module, _}         -> ok;
                    {error, embedded}   -> ok;
                    {error, _}          -> 
                        logger:warning("Invalid restricted_shell module.", []),
                        erlang:throw(error)
                end;
            {ok, _RSM} when (CRS =:= false) -> 
                % Notice that a RS exists but check_rs is false
                case Mode of
                    true ->
                        logger:notice("A restricted_shell is found but check_rs set to false. Continuing anyway.",[]);
                    _ -> skip 
                end;
            _ when (CRS =:= false) -> 
                case Mode of
                    true -> 
                        case get(test) of
                            true -> ok ;
                            _ ->
                            logger:warning("No restricted_shell found and check_rs set to false !",[]),
                            logger:notice("Disable use of a restricted shell is a serious security breach. You are aware, do not blame cipherl !",[]),
                            logger:info("No warning will be raised on this at later security checks.")
                        end;
                    _ -> skip
                end;
            _ when (CRS =:= true) -> 
                logger:warning("No restricted_shell found and check_rs set to true !",[]),
                logger:notice("See https://github.com/crownedgrouse/cipherl/wiki/1---Configuration#check_rs"),
                erlang:throw(error)
        end,
        % Verify mandatory handlers are still attached to gen_event
        % NB : this check MUST be done first and is fatal as missing handler(s) may not be able to handle other checks
        LH = lists:flatmap(fun(X) -> case X of {M, _} -> [M] ; M -> [M] end end, gen_event:which_handlers(cipherl_event)),
        MH = maps:get(security_handler, Conf, []),
        {In, _Out} = lists:partition(fun(Y) ->  lists:member(Y, MH) end, LH),
        case lists:all(fun(Z) -> lists:member(Z, MH) end, In) of
            true  -> ok;
            false -> Missing = MH -- In,
                     logger:alert("Mandatory security handler missing: ~p", [Missing]),
                     gen_event:notify(cipherl_event, {handler_missing, Missing}),
                     erlang:throw(handler_missing)
        end,
        % Verify that 'mod_passphrase' still unloaded after init, and not sticky
        PM = maps:get(mod_passphrase, Conf, ''),
        try
            case code:is_sticky(PM) of
                false -> ok;
                true  -> erlang:throw(error)
            end,
            case code:is_loaded(PM) of
                false     -> ok;
                {file, _} -> erlang:throw(error)
            end
        catch _:_ -> 
                logger:alert("Passphrase is unsafe : mod_passphrase ~p is loaded", [PM]),
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
        % Verify all nodes are known  TODO
        % Verify all node are allowed  TODO
        ok
    catch
        _:_ -> error
    end.

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
-spec get_passphrase(atom(), map()) -> list() | no_return().

get_passphrase(KT, Conf)
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
            Passwd = MP:passwd(KT, node()),
            logger:notice("MP:~p  KT:~p  PASSWD:~p",[MP, KT, Passwd]),
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
%%      !!! should handle "hostname,127.0.1.1" syntax in known_hosts
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
    case lists:member(Host, Hosts) of
        true -> true ;
        false -> 
            Pred = fun(X) -> 
                        case re:run(X, "\\[" ++ Host ++ "\\]") of
                            nomatch    -> false;
                            {match, _} -> true
                        end
                   end,
            lists:any(Pred, Hosts)
    end.

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

%%-------------------------------------------------------------------------
%% @doc Get a Timer based on ticktime
%%-------------------------------------------------------------------------
get_timer() ->
    case net_kernel:get_net_ticktime() of
        ignore -> 5000 ;
        {ongoing_change_to, NT} -> NT * 1000 ;
        NT -> NT * 1000
    end.

%%-------------------------------------------------------------------------
%% @doc Hide sensitive data for logging
%%-------------------------------------------------------------------------
hide_sensitive(D) when is_map(D) ->
    % Remove private entry if any
    maps:update(private, "---8<--- Snip --->8---", D).

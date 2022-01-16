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
    erlang:process_flag(sensitive, true),
    erlang:register(cipherl_ks, self()),
    erlang:process_flag(trap_exit, true),
    logger:info("Starting ~p", [?MODULE]),
    ok = net_kernel:monitor_nodes(true),
    % 
    crypto:start(),
    Private = 
        case ssh_file:user_key('ssh-rsa', []) of
            {ok, Priv}      -> Priv;
            {error, Reason} -> 
                logger:error("ssh_file:user_key failure: ~p", [Reason]),
                exit("No private user key found"), []
        end,
    MO = erlang:element(3, Private),
    PE = erlang:element(4, Private),
    Public  = #'RSAPublicKey'{modulus=MO, publicExponent=PE},

	{ok, monitor_nodes, #{nodes   => #{}
                         ,pending => #{}
                         ,private => Private
                         ,public  => Public
                         }
    }.

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc Handle calls
%% @end
%%-------------------------------------------------------------------------
monitor_nodes({call, {From, Tag}}, EventData, StateData) when is_pid(From)->
    logger:info("~p~p call received from ~p: ~p", [?MODULE, self(), {From, Tag}, EventData]),
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
monitor_nodes(info, {nodedown, Node}, StateData) ->
    % Remove node info in state
    Map1 = maps:remove(Node, maps:get(nodes, StateData)),
    Map2 = maps:remove(Node, maps:get(pending, StateData)),
    NewStateData = maps:merge(StateData, #{nodes => Map1, pending => Map2}),
    logger:info("Removing node: ~p", [Node]),
    {next_state, monitor_nodes, NewStateData};
%%-------------------------------------------------------------------------
%% @doc Node up event
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, {nodeup, Node}, StateData) ->
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
    {next_state, monitor_nodes, NewStateData};
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
    try 
        % Check Node is a pending one
        Node = erlang:element(2, erlang:element(2, Msg)),
        case maps:is_key(Node, maps:get(pending, StateData)) of
            false -> logger:notice("Received auth message for not pending node ~p", [Node]);
            true  -> % Check it is a valid auth message
                     true = check_auth(Msg, StateData) 
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
        _ -> logger:error("Invalid auth message received: ~p", [Msg]),
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
            D when is_record(D, cipherl_chal, 3)
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
        public_key:verify(Bin, sha256, Signed, PubKey) % TODO hash choice
    catch
        C:E:S -> 
            logger:warning("Invalid auth message : ~p", [E]),
            logger:info("~p", [AuthMsg]),
            logger:debug("~p:~p:~p", [C, E, S]),
            false
    end;
check_auth(AuthMsg, _State) ->
    logger:warning("Invalid auth message record"),
    logger:debug("~p",[AuthMsg]),
    false.
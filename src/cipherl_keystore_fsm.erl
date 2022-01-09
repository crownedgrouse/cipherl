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

-include("cipherl_records.hrl").

%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
	gen_statem:start_link(?MODULE, [], []).

%% gen_statem.

callback_mode() ->
	state_functions.

%%-------------------------------------------------------------------------
%% @doc Init function
%% @end
%%-------------------------------------------------------------------------
init([]) ->
    %% TODO let process be sensitive

    logger:info("Starting ~p", [?MODULE]),
    erlang:register(cipherl_ks, self()),
    ok = net_kernel:monitor_nodes(true),
    % 
    Private = 
        case ssh_file:user_key('ssh-rsa', []) of
            {ok, Priv}      -> Priv;
            {error, Reason} -> 
                logger:error("ssh_file:user_key failure: ~p", [Reason]),
                exit("No private user key found"), []
        end,
    crypto:start(),
    Public  = 
        case crypto:privkey_to_pubkey(rsa, Private) of
            {error, Err} -> 
                logger:error("crypto:privkey_to_pubkey failure: ~p", [Err]),
                exit("No public user key found"), [];
            Pub -> Pub
        end,

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
    NewStateData = maps:merge(StateData, #{nodes => Map1}),
    logger:info("Removing node: ~p", [Node]),
    {next_state, monitor_nodes, NewStateData};
%%-------------------------------------------------------------------------
%% @doc Node up event
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, {nodeup, Node}, StateData) ->
    Nonce = erlang:monotonic_time(),
    % Send authenfication challenge to Node
    {cipherl_ks, Node} ! hello_msg(StateData),
    % Add node as Pending with nonce expected
    Map1 = maps:update(maps:get(pending, StateData), Node, Nonce),
    NewStateData = maps:merge(StateData, #{pending => Map1}),
    {next_state, monitor_nodes, NewStateData};
%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(info, EventData, StateData) ->
    logger:info("~p~p info received: ~p", [?MODULE, self(), EventData]),
    {next_state, monitor_nodes, StateData};
%%-------------------------------------------------------------------------
%% @doc Fallback
%% @end
%%-------------------------------------------------------------------------
monitor_nodes(EventType, EventData, StateData) ->
    logger:warning("Unexpected message~nstate: monitor_nodes~nevent: ~p~ndata: ~p~nstate: ~p~n", [EventType, EventData, StateData]),
    {next_state, monitor_nodes, StateData}.

%%=========================================================================
%%-------------------------------------------------------------------------
%% @doc 
%% @end
%%-------------------------------------------------------------------------
handle_event(EventType, EventData, StateName, StateData) ->
    io:format("state: ~p~nevent: ~p~ndata: ~p~nstate: ~p~n", [StateName, EventType, EventData, StateData]),
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
            , pubkey = maps:get(pubkey, State)
            , algos  = ssh:default_algorithms()
            },
    logger:debug(Hello),
    Hello.

%%-------------------------------------------------------------------------
%% @doc Forge a Hello message
%% @end
%%-------------------------------------------------------------------------
-spec check_auth(tuple(), #{}) -> boolean().

check_auth(AuthMsg, State) 
    when  is_record(AuthMsg, cipherl_auth, 2)
    ->
    try 
        {{cipherl_hello, Node, _, PubKey, Algos}, {cipherl_msg, Payload, Signed}} = AuthMsg,
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
            logger:debug("~p:~p:~p", [C, E, S]),
            false
    end;
check_auth(AuthMsg, _State) ->
    logger:warning("Invalid auth message record"),
    logger:debug(AuthMsg),
    false.
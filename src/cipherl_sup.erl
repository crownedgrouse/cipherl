%%%-------------------------------------------------------------------
%%% File:      cipherl_sup.erl
%%% @author    Eric Pailleau <cipherl@crownedgrouse.com>
%%% @copyright 2022 crownedgrouse.com
%%% @doc
%%% Cipherl supervisor
%%% @end
%%%
-module(cipherl_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%-------------------------------------------------------------------------
%% @doc supervisor init
%% @end
%%-------------------------------------------------------------------------
init([]) ->
	Procs = [
    #{id          => event,
      start       => {gen_event, start_link, [{local, cipherl_event}]},
      restart     => transient,
      significant => false,      
      shutdown    => 5000,
      type        => worker,
      modules     => [gen_event]
    },
    #{id          => algos,
      start       => {cipherl_algos_fsm, start_link, []},
      restart     => transient,
      significant => false,      
      shutdown    => 5000,
      type        => worker,
      modules     => [cipherl_algos_fsm]
     },     
    #{id          => keystore,
      start       => {cipherl_keystore_fsm, start_link, []},
      restart     => transient,
      significant => false,      
      shutdown    => 5000,
      type        => worker,
      modules     => [cipherl_keystore_fsm]
     },
    #{id          => server,
      start       => {cipherl_server, start_link, []},
      restart     => transient,
      significant => false,      
      shutdown    => 5000,
      type        => worker,
      modules     => [cipherl_server]
     }             
    ],
	{ok, {{rest_for_one, 1, 5}, Procs}}.

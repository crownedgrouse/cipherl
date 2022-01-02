-module(cipherl_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
	Procs = [
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

%%%-------------------------------------------------------------------
%%% File: cipherl_rs.erl
%%% @author    Eric Pailleau <cipherl@crownedgrouse.com>
%%% @copyright 2022 crownedgrouse.com
%%% @doc
%%% Default Restricted Shell callback for Cipherl
%%% @end
%%%
-module(cipherl_rs).
-export([local_allowed/3, non_local_allowed/3]).


local_allowed(_Func, _ArgList, State) 
    -> {true, State}.


% Redirect any cipherl call to erlang equivalents
non_local_allowed({cipherl, F}, ArgList, State)
   ->
    {{redirect, {erlang, F}, ArgList}, State};
non_local_allowed(_FuncSpec, _ArgList, State) 
    -> {true, State}.

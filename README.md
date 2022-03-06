# [WIP] cipherl

**_note: work in progress, do not use for now_**

`cipherl` is an Erlang application allowing exchange of crypted and signed messages between nodes.

## Why cipherl ?

- Basic Erlang distribution is not secure.  See [this](https://www.erlang.org/doc/reference_manual/distributed.html#security).
- Enabling TLS distribution is not easy. See [this](https://www.erlang.org/doc/apps/ssl/ssl_distribution.html).
- SSH keys are generally available on host.
- TLS distribution does not guarantee message sender identity, nor fraudulent replay of a stolen valid message.

## What cipherl provide ?

- Crypted and signed Erlang messages.
- Non repudiation.
- Replay protection against already used messages.
- SSH key passphrase hidding.
- `known_hosts` use and creation (learning mode).

   See complete [Wiki](https://github.com/crownedgrouse/cipherl/wiki).

## Getting started


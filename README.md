# TARDIGRADE consensus algorithm

This is an implementation of the TARDIGRADE atomic broadcast protocol. The research and protocols for this implementation are explained in "[TARDIGRADE: An Atomic Broadcast Protocol for
Arbitrary Network Conditions](https://eprint.iacr.org/2020/142.pdf)" by Erica Blum, Jonathan Katz, and Julian Loss, 2021.

The building blocks are following sub-protocols.

### Reliable Broadcast
A committee-based reliable broadcast protocol based on [Bracha's Broadcast](https://core.ac.uk/download/pdf/82523202.pdf)

### Block Agreement
A block-agreement protocol for synchronous consensus.

### Asynchronous Common Subset
A committee-based terminating ACS protocol.

### Binary Agreement
An asynchronous byzantine agreement protocol based on [Mostéfaoui et al.](https://hal.inria.fr/hal-00944019v2/document) using a common coin based on threshold signatures ([Cachin et al.](https://allquantor.at/blockchainbib/pdf/cachin2000random.pdf)). Ported from [Honey Badger BFT](https://github.com/initc3/HoneyBadgerBFT-Python/)

### TARDIGRADE
The top level protocol that combines all the above sub-protocols into a complete consensus protocol.
The goal of this protocol is to maintain liveness under varying network conditions and byzantine faults.

#### Requirements
```shell
go get github.com/niclabs/tcrsa
go get github.com/niclabs/tcpaillier
```

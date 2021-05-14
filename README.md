# FairThunder

For both `downloading` and `streaming` settings, the implementations are provided. Specifically,

### backend
- This folder provides the code (implemented in python 3.7) that can generate all the test data to interact with the Ethereum Ropsten network.

### contract_solidity
- This folder provides the code (implemented in Solidity 0.5.10+) of smart contract.

### streaming_round_demo
- This folder provides the code (implemented in Java 1.8.0_275) and starting script to test the latency of streaming a set of content chunks, i.e., multiple delivery rounds, in the FairThunder streaming setting. The experiment is conducted in both LAN and WAN.

Note: the contracts in this repository are used as a proof-of-concept, and are not audited for implementation bugs. Hence, they should be used with caution.

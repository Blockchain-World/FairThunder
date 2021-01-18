pragma solidity ^0.5.10;
pragma experimental ABIEncoderV2;

import {FTSU} from "./FairThunder_Stream_Utility.sol";

/**
 * FairThunder streaming optimistic mode.
 **/

// Abstract 'FairThunderStreamingPessimistic' contract
contract FairThunderStreamingPessimistic {
    function validatePoM(uint, bytes32[] memory, bytes memory, bytes32, bytes memory, bytes32, FTSU.MerkleProof[] memory, bytes32) public returns (bool);
}

contract FairThunderStreamingOptimistic{

    address payable public provider;
    address payable public deliverer;
    address payable public consumer;
    
    uint public timeout_round; // timer for state round
    uint public timeout_finish; // timer for finishing the protocol session
    uint public timeout_receive; // timer for confirming that C receives all or partial chunks
    
    // Fairthunder pessimistic contract address (for streaming)
    address payable public FTSPContractAddress = XXX_FTSPContractAddress_XXX;
    FairThunderStreamingPessimistic FTSP = FairThunderStreamingPessimistic(FTSPContractAddress);

    enum state {started, joined, ready, initiated, received, delivered, revealed, sold, not_sold}
    
    state public round;

    // The merkle root of the content m
    bytes32 public root_m;
    
    // The number of content chunks
    uint public n = 0;
    
    // The number of 32-byte sub-chunks: chunkSize / 32 (bytes32)
    uint constant chunkLength = 16;
    
    // The payment for delivery per chunk (wei)
    uint public payment_P = 0;
    
    // The payment for providing per chunk (wei)
    uint public payment_C = 0;
    
    // The penalty fee in case P behaves dishonestly
    uint public payment_plt = 0;
    
    // The number of delivered chunks
    uint public ctr = 0;
    
    // It allows the deliverer can only be paid once
    bool paid_for_delivery = false;
    
    // It allows the provider can only be paid once
    bool paid_for_revealing = false;
    
    function inState(state s) internal {
        round = s;
        timeout_round = now + 10 minutes;
    }
    
    constructor() payable public {
        provider = msg.sender; // store pk_P
        timeout_round = now;
    }
    
    // Phase I: Prepare (typically only need to be executed once)
    function start(bytes32 _root_m, uint _n, uint _payment_P, uint _payment_C, uint _payment_plt) payable public {
        require(msg.sender == provider);
        assert(msg.value >= _payment_P*_n);
        assert(_payment_C >= _payment_P);
        root_m = _root_m;       // store root_m
        n = _n;                 // store n
        payment_P = _payment_P; // store payment_P
        payment_C = _payment_C; // store payment_C
        payment_plt = _payment_plt; // store payment_plt
        inState(state.started);
    }
    
    // The provider choose one candidate as the deliverer of its own choice
    function join() public {
        require(round == state.started);
        deliverer = msg.sender;
        inState(state.joined);
    }
    
    function prepared() public {
        require(now <timeout_round);
        require(msg.sender == deliverer);
        require(round == state.joined);
        inState(state.ready);
    }
    
    // Phase II: Stream
    function consume() payable public {
        assert(msg.value >= n*payment_C);
        require(round == state.ready);
        consumer = msg.sender;         // store pk_C
        timeout_receive = now + 20 minutes; // start the timer T_receive
        timeout_finish = now + 30 minutes; // start the timer T_finish
        inState(state.initiated);
    }
    
    // The consumer actively confirm that received the delivered chunks and keys
    function received() public {
        require(now < timeout_receive);
        require(round == state.initiated);
        inState(state.received);
        selfdestruct(consumer);
    }
    
    // The timeout_receive times out, even the customer does not confirm to the contract, the state will be set as "received"
    function receiveTimeout() public {
        require(now >= timeout_receive);
        require(round == state.initiated);
        inState(state.received);
        selfdestruct(consumer);
    }
    
    // Resolve dispute during the streaming, and then if indeed misbehavior is detected, the state will be set as "received"
    function PoM(uint _i, bytes32[] memory _c_i, bytes memory _signature_c_i, bytes32 _k_i, bytes memory _signature_k_i, bytes32 _m_i_hash, FTSU.MerkleProof[] memory _merkle_proof) public payable {
        require(now < timeout_receive);
        require(round == state.initiated);
        if (FTSP.validatePoM(_i, _c_i, _signature_c_i, _k_i, _signature_k_i, _m_i_hash, _merkle_proof, root_m)) {
            // if the provider P indeed misbehaves, e.g., revealed a wrong key
            consumer.transfer(payment_plt);
            inState(state.received);
            selfdestruct(consumer);
        }
    }
    
    // Verify the receipt from the deliverer
    function claimDelivery(bytes memory _signature_CD, uint _i) public {
        require(paid_for_delivery == false);
        require(now < timeout_finish);
        require(msg.sender == deliverer);
        require(round == state.initiated || round == state.received || round == state.revealed);
        if (ctr == 0) {
            bytes32 deliverer_receipt_hash = FTSU.prefixed(keccak256(abi.encodePacked("chunkReceipt", _i, consumer, msg.sender, root_m, this)));
            if (FTSU.recoverSigner(deliverer_receipt_hash, _signature_CD) == consumer) {
                assert(_i > 0 && _i <= n);
                ctr = _i; // update ctr
            }
        }
        if (ctr > 0 && ctr < n) {
            deliverer.transfer(ctr * payment_P);
            provider.transfer((n - ctr) * payment_P);
        } else if (ctr == n) {
            deliverer.transfer(n * payment_P);
        }
        paid_for_delivery = true;
        inState(state.delivered);
        // selfdestruct(deliverer);
    }
    
    // Verify the receipt from the provider
    function claimRevealing(bytes memory _signature_CP, uint _i) public {
        require(paid_for_revealing == false);
        require(now < timeout_finish);
        require(msg.sender == provider);
        require(round == state.initiated || round == state.received || round == state.delivered);
        if (ctr == 0) {
            bytes32 provider_receipt_hash = FTSU.prefixed(keccak256(abi.encodePacked("keyReceipt", _i, consumer, msg.sender, root_m, this)));
            if (FTSU.recoverSigner(provider_receipt_hash, _signature_CP) == consumer) {
                assert(_i > 0 && _i <= n);
                ctr = _i; // update ctr
            }
        }
        if (ctr > 0 && ctr < n) {
            provider.transfer(ctr * payment_C);
            consumer.transfer((n - ctr) * payment_C);
        } else if (ctr == n) {
            provider.transfer(n * payment_C);
        }
        paid_for_revealing = true;
        inState(state.revealed);
        // selfdestruct(provider);
    }
    
    // The timeout_finish times out, the state will be set as "sold" or "not_sold"
    function finishTimeout() public {
        require(now >= timeout_finish);
        if (round == state.delivered || round == state.revealed) {
            inState(state.sold);
        } else {
            inState(state.not_sold);
        }
    }
    
}

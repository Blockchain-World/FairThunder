pragma solidity ^0.5.10;
pragma experimental ABIEncoderV2;

import {FTSU} from "./FairThunder_Stream_Utility.sol";

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
    address payable public FTSPContractAddress = "XXX_FT_Streaming_Pessimistic_Contract_Address_XXX";
    FairThunderStreamingPessimistic FTSP = FairThunderStreamingPessimistic(FTSPContractAddress);

    enum state {started, joined, ready, initiated, received, payingDelivery, payingRevealing, sold, not_sold}
    
    state public round;

    // The merkle root of the content m
    bytes32 public root_m;

    // the times of repeatable delivery
    uint public theta = 0; 
    
    // The number of content chunks
    uint public n = 0;
    
    // The number of 32-byte sub-chunks: chunkSize / 32 (bytes32)
    uint constant chunkLength = XXX;
    
    // The payment for delivery per chunk
    uint public payment_P = 0;
    
    // The payment for providing per chunk
    uint public payment_C = 0;
    
    // penalty fee to discourage the misbehavior of the provider
    uint public payment_pf = 0;

    // penalty flag
    bool public plt = false;
    
    // The (finally determined) number of delivered chunks 
    uint public ctr = 0;
    
    // The index of the receipt from deliverer
    uint public ctr_D = 0;
    
    // The index of the receipt from provider
    uint public ctr_P = 0;

    // The start index (1-indexed) of request content
    uint public a = 0;
    
    function inState(state s) internal {
        round = s;
        timeout_round = now + 10 minutes;
    }
    
    constructor() payable public {
        provider = msg.sender; // store pk_P
        timeout_round = now;
    }
    
    // Phase I: Prepare
    function start(bytes32 _root_m, uint _theta, uint _n, uint _payment_P, uint _payment_C, uint _payment_pf) payable public {
        require(msg.sender == provider);
        assert(msg.value >= _theta*(_payment_P*_n+_payment_pf));
        assert(_payment_C >= _payment_P);
        assert(_payment_pf >= _payment_C*_n/2); // the penalty fee is required to be proportional to the (n*payment_C) so the provider cannot delibrately low it
        root_m = _root_m;       // store root_m
        theta = _theta;         // store theta
        n = _n;                 // store n
        payment_P = _payment_P; // store payment_P
        payment_C = _payment_C; // store payment_C
        payment_pf = _payment_pf; // store payment_pf
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
    function consume(uint _a) payable public {
        assert(msg.value >= (n - _a + 1) * payment_C);
        require(theta > 0);
        require(_a >= 1 && _a <= n);
        require(round == state.ready);
        a = _a;                        // store a
        consumer = msg.sender;         // store pk_C
        timeout_receive = now + 20 minutes; // start the timer T_receive
        timeout_finish = now + 30 minutes; // start the timer T_finish
        inState(state.initiated);
    }
    
    // The consumer actively confirms the delivered chunks and keys are received
    function received() public {
        require(now < timeout_receive);
        require(round == state.initiated);
        inState(state.received);
    }
    
    // The timeout_receive times out, even though the customer does not confirm to the contract, the state will be set as "received"
    function receiveTimeout() public {
        require(now >= timeout_receive);
        require(round == state.initiated);
        inState(state.received);
    }
    
    // Resolve dispute during the streaming, and then if indeed misbehavior is detected, the state will be set as "received"
    function PoM(uint _i, bytes32[] memory _c_i, bytes memory _signature_c_i, bytes32 _k_i, bytes memory _signature_k_i, bytes32 _m_i_hash, FTSU.MerkleProof[] memory _merkle_proof) public payable {
        require(now < timeout_receive);
        require(_i >= a && _i <= n);
        require(round == state.initiated);
        if (FTSP.validatePoM(_i, _c_i, _signature_c_i, _k_i, _signature_k_i, _m_i_hash, _merkle_proof, root_m)) {
            // if the provider P indeed misbehaves, e.g., revealed a wrong key
            plt = true;
            inState(state.received);
        }
    }
    
    // Verify the receipt from the deliverer
    function claimDelivery(bytes memory _signature_CD, uint _i) public {
        require(now < timeout_finish);
        require(msg.sender == deliverer);
        require((_i >= a && _i <= n) || round == state.received || round == state.payingRevealing);
        if (ctr == 0) {
            bytes32 deliverer_receipt_hash = FTSU.prefixed(keccak256(abi.encodePacked("chunkReceipt", _i, consumer, msg.sender, root_m, this)));
            if (FTSU.recoverSigner(deliverer_receipt_hash, _signature_CD) == consumer) {
                ctr_D = _i - a + 1; // update ctr_D
                inState(state.payingDelivery);
            }
        }
    }
    
    // Verify the receipt from the provider
    function claimRevealing(bytes memory _signature_CP, uint _i) public {
        require(now < timeout_finish);
        require(msg.sender == provider);
        require((_i >= a && _i <= n) || round == state.received || round == state.payingDelivery);
        if (ctr == 0) {
            bytes32 provider_receipt_hash = FTSU.prefixed(keccak256(abi.encodePacked("keyReceipt", _i, consumer, msg.sender, root_m, this)));
            if (FTSU.recoverSigner(provider_receipt_hash, _signature_CP) == consumer) {
                ctr_P = _i - a + 1; // update ctr_P
                inState(state.payingRevealing);
            }
        }
    }
    
    // After the timeout_finish times out, determine the final ctr, and the state will be set as "sold" or "not_sold"
    function finishTimeout() public {
        require(now >= timeout_finish);
        // Determine the final ctr = max{ctr_D, ctr_P}
        if (ctr_D >= ctr_P) {
            ctr = ctr_D;
        } else {
            ctr = ctr_P;
        }
        // Distribute payment to parties
        deliverer.transfer(ctr * payment_P);
        if (plt) {
            consumer.transfer((n - a + 1 - ctr) * payment_C + payment_pf);
            provider.transfer((n - ctr) * payment_P + (ctr * payment_C));
        } else {
            provider.transfer((n - ctr) * payment_P + ctr * payment_C + payment_pf);
            consumer.transfer((n - a + 1 - ctr) * payment_C);
        }
        if (ctr > 0) {
            inState(state.sold);
        } else {
            inState(state.not_sold);
        }
    }

    // when the protocol instance completes, reset to the ready state and receive other consumers' request (i.e., repeatable delivery)
    function reset() public {
        require(msg.sender == provider);
        require(round == state.sold || round == state.not_sold);
        ctr = 0;
        a = 0;
        ctr_D = 0;
        ctr_P = 0;
        timeout_receive = 0;
        timeout_finish = 0;
        theta = theta - 1;
        consumer = 0x0000000000000000000000000000000000000000; // nullify consumer's address
        inState(state.ready);
    }

}

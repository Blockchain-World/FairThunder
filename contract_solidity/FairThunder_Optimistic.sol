pragma solidity ^0.5.10;
pragma experimental ABIEncoderV2;

import {FTU} from "./FairThunderUtility.sol";
import "./altbn128.sol";

/**
 * FairThunder optimistic mode.
 * It also contains a function that calls a 'FairThunderPessimistic' contract for dispute resolution.
 **/

// Abstract 'FairThunderPessimistic' contract
contract FairThunderPessimistic {
    function validateRKeys(uint, uint, uint[] memory) public returns (bool);
    function onChainParams(uint, uint, bytes32, BN128Curve.G1Point memory) public;
    function validatePoM(uint[] memory, bytes32[] memory, bytes memory, bytes32, FTU.MerkleProof[] memory, FTU.SubmittedERK[] memory, FTU.ERK[] memory, FTU.SubmittedRK[] memory, FTU.VPKEProof[] memory) public returns (bool);
    function () external payable;
}

contract FairThunderOptimistic{
    
    using FTU for FTU.ERK;
    using FTU for FTU.SubmittedERK;
    using FTU for FTU.SubmittedRK;
    using FTU for FTU.VPKEProof;
    
    event emitErk(uint, BN128Curve.G1Point, BN128Curve.G1Point, BN128Curve.G1Point, BN128Curve.G1Point);
    
    address payable public provider;
    address payable public deliverer;
    address payable public consumer;
    BN128Curve.G1Point public vpk_consumer;
    
    // Fairthunder pessimistic contract address
    address payable public FTPContractAddress = 0x843036ABCd1e5Bc09cDc7c6CAb28C4D3d04BBeF1;
    FairThunderPessimistic FTP = FairThunderPessimistic(FTPContractAddress);
    
    uint public timeout_round;
    uint public timeout_delivered;
    uint public timeout_dispute;
    
    enum state {started, joined, ready, initiated, revealing, revealed, sold, not_sold}
    
    state public round;

    // The merkle root of the content m
    bytes32 public root_m;
    
    // The number of content chunks
    uint public n = 0;
    
    // The number of 32-byte sub-chunks: chunkSize / 32 (bytes32)
    uint constant chunkLength = 2;
    
    // The payment for delivery per chunk (wei)
    uint public payment_P = 0;
    
    // The payment for providing per chunk (wei)
    uint public payment_C = 0;
    
    // The number of delivered chunks
    uint public ctr = 0;
    
    // The revealed encrypted elements' information for 
    // recovering ctr (ctr<=n) sub-keys
    FTU.ERK[] erk;
    
    modifier allowed(address addr, state s){
        require(now < timeout_round);
        require(round == s);
        require(msg.sender == addr);
        _;
    }
    
    function inState(state s) internal {
        round = s;
        timeout_round = now + 10 minutes;
    }
    
    constructor() payable public {
        provider = msg.sender; // store pk_P
        timeout_round = now;
    }
    
    // Phase I: Prepare (typically only need to be executed once)
    function start(bytes32 _root_m, uint _n, uint _payment_P, uint _payment_C) payable public {
        require(msg.sender == provider);
        assert(msg.value >= _payment_P*_n);
        assert(_payment_C >= _payment_P);
        root_m = _root_m;       // store root_m
        n = _n;                 // store n
        payment_P = _payment_P; // store payment_P
        payment_C = _payment_C; // store payment_C
        inState(state.started);
    }
    
    // We omit the procedure that the provider choose one as the deliverer
    // as this is an orthogonal problem
    function join() public {
        require(round == state.started);
        deliverer = msg.sender;
        inState(state.joined);
    }
    
    function prepared() allowed(deliverer, state.joined) public {
        inState(state.ready);
    }
    
    // Phase II: Deliver
    function consume(BN128Curve.G1Point memory _vpk_consumer) payable public {
        assert(msg.value >= n*payment_C);
        require(round == state.ready);
        consumer = msg.sender;         // store pk_C
        vpk_consumer = _vpk_consumer;  // store vpk_consumer
        timeout_delivered = now + 10 minutes; // start the timer
        inState(state.initiated);
    }
    
    // Verify the PoD from the deliverer
    function verifyPoD(uint _i, bytes memory _signature_C) allowed(deliverer, state.initiated) public returns (bool) {
        require(_i <= n);
        bytes32 PoD = FTU.prefixed(keccak256(abi.encodePacked(_i, consumer, msg.sender, root_m, this)));
        if (FTU.recoverSigner(PoD, _signature_C) == consumer) {
            ctr = _i; // update ctr
            return true;
        }
        return false;
    }
    
    // Timeout_delivered times out
    function deliveredTimeout() payable public {
        require(now > timeout_delivered);
        require(ctr >= 0 && ctr <= n);
        // if ctr is not updated (i.e., ctr == 0), the state will not be updated untill getPoD() 
        // is executed (i.e., D claimed payment and update ctr)
        if ((ctr > 0) && (ctr <= n)) {
            if (ctr == n) {
                deliverer.transfer(payment_P*n);
            } else {
                provider.transfer(payment_P*(n-ctr));
                deliverer.transfer(payment_P*ctr);
            }
            inState(state.revealing);
            selfdestruct(deliverer);
        }
    }
    
    function delivered() payable allowed(consumer, state.initiated) public {
        require(now < timeout_delivered);
        require(ctr >= 0 && ctr <= n);
        // if ctr is not updated (i.e., ctr == 0), the state will not be updated untill getPoD()
        // is executed (i.e., D claimed payment and update ctr)
        if ((ctr > 0) && (ctr <= n)) {
            if (ctr == n) {
                deliverer.transfer(payment_P*n);
            } else {
                provider.transfer(payment_P*(n-ctr));
                deliverer.transfer(payment_P*ctr);
            }
            inState(state.revealing);
            selfdestruct(deliverer);
        }
    }
    
    // Phase III: Reveal 
    
    // for example,
    //     position:    [1, 5], 1 and 5 are index in KT
    // sub-position:      1-0      1-1    5-0      5-1
    //           c1:    [[X, Y], [X, Y], [X, Y], [X, Y]]
    //           c2:    [[X, Y], [X, Y], [X, Y], [X, Y]]
    function revealKeys(uint[] memory _positions, BN128Curve.G1Point[] memory _c_1s, BN128Curve.G1Point[] memory _c_2s) allowed(provider, state.revealing) public {
        assert ((_c_1s.length == _c_2s.length) && (_c_1s.length == 2 * _positions.length));
        bytes32 erk_hash = "";
        for (uint i = 0; i < _positions.length; i++){
            emit emitErk(_positions[i], _c_1s[2*i], _c_2s[2*i], _c_1s[2*i+1], _c_2s[2*i+1]);
            erk_hash = keccak256(abi.encodePacked(erk_hash, _c_1s[2*i].X, _c_1s[2*i].Y, _c_2s[2*i].X, _c_2s[2*i].Y, _c_1s[2*i+1].X, _c_1s[2*i+1].Y, _c_2s[2*i+1].X, _c_2s[2*i+1].Y));
            erk.push(FTU.ERK(_positions[i], erk_hash));
        }
        timeout_dispute = now + 20 minutes;
        inState(state.revealed);
    }
    
    
    // In optimistic case, there is no dispute between the consumer and the provider
    function payout() payable public {
        require(round == state.revealed);
        require(now > timeout_dispute);
        if((ctr > 0) && (ctr <= n)){
            if(ctr == n){
                provider.transfer(payment_C*n);
            }else{
                provider.transfer(payment_C*ctr);
                consumer.transfer(payment_C*(n-ctr));
            }
            inState(state.sold);
            selfdestruct(provider);
            selfdestruct(consumer);
        }
    }
    
    function refund() public {
        consumer.transfer(n * payment_C);
        inState(state.not_sold);
        selfdestruct(consumer);
        selfdestruct(provider);
    }
    
    // Below is about dispute resolution
    function wrongRK() allowed(consumer, state.revealed) public {
        require(now < timeout_dispute);
        uint[] memory erk_indexes = new uint[](erk.length);
        for (uint i = 0; i < erk.length; i++) {
            erk_indexes[i] = erk[i].position;
        }
        if (!FTP.validateRKeys(n, ctr, erk_indexes)) {
            // !validateRKeys returns true (i.e, validateRKeys returns false) means that the revealed keys
            // cannot recover the desired number of decrption keys, namely P behaves dishonestly
            refund();
        }
    }
     
    function PoM(uint[] memory _i_j_steps, bytes32[] memory _c_i, bytes memory _signature_i_P, bytes32 _m_i_hash, FTU.MerkleProof[] memory _merkleProof, FTU.SubmittedERK[] memory _st_erk, FTU.SubmittedRK[] memory _st_rk, FTU.VPKEProof[] memory _vpke_proof) allowed(consumer, state.revealed) public {
        require(now < timeout_dispute);
        FTP.onChainParams(n, ctr, root_m, vpk_consumer);
        if (FTP.validatePoM(_i_j_steps, _c_i, _signature_i_P, _m_i_hash, _merkleProof, _st_erk, erk, _st_rk, _vpke_proof)) {
            // PoM verification returns true means that P behaves dishonestly (i.e., revealed the wrong keys)
            refund();
        }
    }
    
}

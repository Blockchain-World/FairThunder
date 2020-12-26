pragma solidity ^0.5.10;

import "./altbn128.sol";

library FTU {
    
    struct ERK {
        uint position; // the position in KT
        bytes32 erk_hash; // the hash value of erk stored on-chain
    }
    
    struct SubmittedERK {
        uint position; // the position index in KT
        uint C1_X;   // C1.X
        uint C1_Y;   // C1.Y
        uint C2_X;   // C2.X
        uint C2_Y;   // C2.Y
    }
    
    struct SubmittedRK {
        uint position; // the position in KT
        bytes32 value; // the submitted rk value
    }
    
    struct VPKEProof {
        uint position; // the position is the index in KT
        uint A_X; // A.X on BN128Curve
        uint A_Y; // A.Y on BN128Curve
        uint B_X; // B.X on BN128Curve
        uint B_Y; // B.Y on BN128Curve
        uint Z;   // Z
    }
    
    struct MerkleProof {
        bytes32 label; // the hash value of the sibling
        uint posIden; // the binary bit indicating the position
    }
    
    // Functions for signature verification
    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s){
        require(sig.length == 65);
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }
    
    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address){
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(message, v, r, s);
    }
    
    function prefixed(bytes32 hash) internal pure returns (bytes32){
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    
}

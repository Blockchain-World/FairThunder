pragma solidity ^0.5.10;
pragma experimental ABIEncoderV2;

import {FTSU} from "./FairThunder_Stream_Utility.sol";

/**
 * FairThunder streaming pessimistic mode for dispute resolution.
 **/

contract FairThunderStreamingPessimistic{

    address payable public provider;

    // The number of sub-chunks (i.e, 32bytes) included in a content chunk, namely chunkLength = chunk_size / 32 bytes
    uint constant chunkLength = XXX;
    
    constructor () payable public {
        provider = msg.sender;
    }
    
    function validateChunkSig(uint _i, bytes32[] memory _c_i, bytes memory _signature) public view returns (bool){
        // recreates chunk cipher hash
        bytes32 h = _c_i[0];
        if (_c_i.length == 1) {
            h = keccak256(abi.encodePacked(h));
        } else {
            for (uint i = 1; i < chunkLength; i++) {
                h = keccak256(abi.encodePacked(h, _c_i[i]));
            }
        }
        // recreates the signed message 
        bytes32 _chunk = FTSU.prefixed(keccak256(abi.encodePacked(_i, h)));
        if (FTSU.recoverSigner(_chunk, _signature) == provider) {
            return true;
        } else {
            return false;
        }
    }
    
    function validateKeySig(uint _i, bytes32 _k_i, bytes memory _signature) public view returns (bool){
        // recreates the signed message 
        bytes32 _key = FTSU.prefixed(keccak256(abi.encodePacked(_i, _k_i)));
        if (FTSU.recoverSigner(_key, _signature) == provider) {
            return true;
        } else {
            return false;
        }
    }
    
    function vrfyMTP(FTSU.MerkleProof[] memory _merkleProof, bytes32 _m_i_hash, bytes32 _root_m) public pure returns (bool) {
        bytes32 hash_temp = _m_i_hash;
        for (uint i = 0; i < _merkleProof.length; i++){
            if (_merkleProof[i].posIden == 0){
                hash_temp = keccak256(abi.encodePacked(hash_temp, _merkleProof[i].label));
            }
            if (_merkleProof[i].posIden == 1){
                hash_temp = keccak256(abi.encodePacked(_merkleProof[i].label, hash_temp));
            }
        }
        return (hash_temp == _root_m);
    }
    
    function decrypt(bytes32[] memory _c_i, bytes32 _chunk_key) public pure returns (bytes32[chunkLength] memory) {
        bytes32[chunkLength] memory decrypted_result;
        for (uint j = 0; j < chunkLength; j++){
            decrypted_result[j] = keccak256(abi.encodePacked(j, _chunk_key)) ^ _c_i[j];
        }
        return decrypted_result;
    }
    
    function chunk_hash(bytes32[chunkLength] memory _chunk) pure public returns (bytes32) {
        bytes32 _chunk_hash = "";
        if (chunkLength == 1){
            return keccak256(abi.encodePacked(_chunk[0]));
        } else {
            _chunk_hash = _chunk[0];
            for (uint i = 1; i < chunkLength; i++){
                _chunk_hash = keccak256(abi.encodePacked(_chunk_hash, _chunk[i]));
            }
        }
        return _chunk_hash;
    }
    
    // Dispute resolution in during the Stream phase if the consumer found invalid decrypted chunks
    function validatePoM(uint _i, bytes32[] memory _c_i, bytes memory _signature_c_i, bytes32 _k_i, bytes memory _signature_k_i, bytes32 _m_i_hash, FTSU.MerkleProof[] memory _merkle_proof, bytes32 _root_m) public view returns (bool){
        // Validate the chunk is signed by the provider
        if (validateChunkSig(_i, _c_i, _signature_c_i)) {
            // Validate the sub-key is signed by the provider
            if (validateKeySig(_i, _k_i, _signature_k_i)) {
                // Validate the merkle proof of the i-th leaf node of MT 
                if (vrfyMTP(_merkle_proof, _m_i_hash, _root_m)) {
                    // Decrypt the chunk
                    bytes32[chunkLength] memory decrypted_chunk = decrypt(_c_i, _k_i);
                    // proof of misbehavior
                    if (chunk_hash(decrypted_chunk) != _m_i_hash) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}

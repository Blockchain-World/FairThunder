pragma solidity ^0.5.10;
pragma experimental ABIEncoderV2;

import "./altbn128.sol";
import "./FairThunderUtility.sol";

/**
 * FairThunder pessimistic mode for dispute resolution, i.e., validateRKeys(), ValidatePoM().
 **/

contract FairThunderPessimistic {
    
    using FTU for FTU.ERK;
    using FTU for FTU.SubmittedERK;
    using FTU for FTU.SubmittedRK;
    using FTU for FTU.VPKEProof;
    using FTU for FTU.MerkleProof;
    
    address payable public provider;
    
    // The merkle root of the content m
    bytes32 root_m;
    // The number of content chunks
    uint public n;
    // The number (counter) of delivered chunks
    uint public ctr;
    
    BN128Curve.G1Point vpk_consumer;
    
    // The number of sub-chunks (i.e, 32bytes) included in a content chunk
    uint constant chunkLength = XXX;

    constructor () payable public {
        provider = msg.sender;
    }
    
    // Receive common parameters from FairThunder optimistic contract 
    function onChainParams(uint _n, uint _ctr, bytes32 _root_m, BN128Curve.G1Point memory _vpk_consumer) public {
        n = _n;
        ctr = _ctr;
        root_m = _root_m;
        vpk_consumer = _vpk_consumer;
    }
    
    function log2_alg_floor(uint _xx) pure public returns (uint) {
        uint y = 0;
        if (_xx >= 2**128) { _xx >>= 128; y += 128; }
        if (_xx >= 2**64)  { _xx >>= 64; y += 64; }
        if (_xx >= 2**32)  { _xx >>= 32; y += 32; }
        if (_xx >= 2**16)  { _xx >>= 16; y += 16; }
        if (_xx >= 2**8)   { _xx >>= 8; y += 8; }
        if (_xx >= 2**4)   { _xx >>= 4; y += 4; }
        if (_xx >= 2**2)   { _xx >>= 2; y += 2; }
        if (_xx >= 2**1)   { y += 1; }
        return y;
    }
    
    // Check if correct number (i.e., ctr) of sub-keys can be recovered
    function validateRKeys(uint _n, uint _ctr, uint[] memory _erk_indexes) public pure returns (bool) {
        if ((_n == _ctr) && (_erk_indexes.length == 1) && (_erk_indexes[0] == 0)) {
            // (_n == _ctr) means that the deliverer delivers all the chunks
            // (_erk_indexes.length == 1) means that the provider reveals one key
            // (_erk_indexes[0] == 0) means that the revealed key is the root key
            // which is capable of recovering all the sub-keys for chunks
            return true;
        }
        uint height = log2_alg_floor(_n);
        uint[] memory chunks_index = new uint[](_ctr);
        uint index = _n - 1;
        for (uint i = 0; i < _ctr; i++) {
            chunks_index[i] = index;
            index++;
        }
        for (uint i = 0; i < _erk_indexes.length; i++){
            uint j = _erk_indexes[i];
            uint d_j = height - log2_alg_floor(j+1);
            uint l_j = j;
            uint r_j = j;
            if (d_j == 0){
                delete chunks_index[j-(_n-1)];
            } else {
                while(d_j > 0) {
                    l_j = 2 * l_j + 1;
                    r_j = 2 * r_j + 2;
                    d_j = d_j - 1;
                }
            }
            for(uint x = l_j; x <= r_j; x++){
                delete chunks_index[x-(_n-1)];
            }
        }
        // Delete will only set the value as default, and will not remove the place
        // So we need to check each position in chunks_index
        for(uint y = 0; y < _ctr; y++) {
            if (chunks_index[y] != 0) {
                return false;
            }
        }
        return true;
    }
    
    function compute_nizk_challenge(BN128Curve.G1Point memory _A, BN128Curve.G1Point memory _B, BN128Curve.G1Point memory _c_1, BN128Curve.G1Point memory _c_2, bytes32 _rk_i) public view returns (uint) {
        bytes32 g_hash = keccak256(abi.encodePacked(BN128Curve.P1().X, BN128Curve.P1().Y));
        bytes32 A_hash = keccak256(abi.encodePacked(_A.X, _A.Y));
        bytes32 B_hash = keccak256(abi.encodePacked(_B.X, _B.Y));
        bytes32 vpk_hash = keccak256(abi.encodePacked(vpk_consumer.X, vpk_consumer.Y));
        bytes32 c_1_hash = keccak256(abi.encodePacked(_c_1.X, _c_1.Y));
        bytes32 c_2_hash = keccak256(abi.encodePacked(_c_2.X, _c_2.Y));
        bytes32 rk_i_hash_rs = keccak256(abi.encodePacked(uint(_rk_i)>>128));
        bytes32 C = keccak256(abi.encodePacked(g_hash, A_hash, B_hash, vpk_hash, c_1_hash, c_2_hash, rk_i_hash_rs)) >> 160;
        return uint(C);
    }
    
    function computeEq1L(uint _Z) public view returns (BN128Curve.G1Point memory) {
        return BN128Curve.g1mul(BN128Curve.P1(), _Z);
    }
    
    function computeEq1R(BN128Curve.G1Point memory _A, uint _C) public view returns (BN128Curve.G1Point memory) {
        return BN128Curve.g1add(_A, BN128Curve.g1mul(vpk_consumer, _C));
    }
    
    function computeEq2L(bytes32 _m, uint[] memory _steps_C_Z, BN128Curve.G1Point memory _c_1) public view returns (BN128Curve.G1Point memory) {
        uint y;
        uint beta;
        uint x = (uint(_m) >> 128) * 128 + _steps_C_Z[0];
        (beta, y) = BN128Curve.FindYforX(x);
        return BN128Curve.g1add(BN128Curve.g1mul(BN128Curve.G1Point(x, y), _steps_C_Z[1]), BN128Curve.g1mul(_c_1, _steps_C_Z[2]));
    }
    
    function computeEq2R(BN128Curve.G1Point memory _B, BN128Curve.G1Point memory _c_2, uint _C) public view returns (BN128Curve.G1Point memory) {
        return BN128Curve.g1add(_B, BN128Curve.g1mul(_c_2, _C));
    }
    
    function check_onchain_erk(uint _j, FTU.SubmittedERK[] memory _st_erk, FTU.ERK[] memory _erk) public pure returns (bool) {
        bytes32 erk_hash_submitted = "";
        erk_hash_submitted = keccak256(abi.encodePacked(erk_hash_submitted, _st_erk[0].C1_X, _st_erk[0].C1_Y, _st_erk[0].C2_X, _st_erk[0].C2_Y, _st_erk[1].C1_X, _st_erk[1].C1_Y, _st_erk[1].C2_X, _st_erk[1].C2_Y));
        // Ensure that the submitted erk hash ==  the erk hash on-chain
        return (erk_hash_submitted == _erk[_j].erk_hash);
    }
    
    // It verifies that the item in erk can decrypt to the corresponding item in rk
    //  _i_j_steps: [uint _i, uint _j, uint _step1, uint _step2]
    //     _st_erk: [[c1.X, c1.Y, c2.X, c2.Y], [c1.X, c1.Y, c2.X, c2.Y], ...]
    //      _st_rk: [[1, "0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"], [1, "0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"], ...]
    // _vpke_proof: [[A.X, A.Y, B.X, B.Y, Z] , [A.X, A.Y, B.X, B.Y, Z], ...]
    function verify_PKE(uint[] memory _i_j_steps, FTU.SubmittedERK[] memory _st_erk, FTU.SubmittedRK[] memory _st_rk, FTU.VPKEProof[] memory _vpke_proof)  public view returns(bool) {
        bool res = true;
        // Just need one element in KT, which contains two 128-bit hash value, and in total 256 bits hash value
        for (uint i = 0; i < 2; i++) {
            // uint C = compute_nizk_challenge(A, B, c_1, c_2, _st_rk.value);
            uint C = compute_nizk_challenge(BN128Curve.G1Point(_vpke_proof[i].A_X, _vpke_proof[i].A_Y), BN128Curve.G1Point(_vpke_proof[i].B_X, _vpke_proof[i].B_Y),
            BN128Curve.G1Point(_st_erk[i].C1_X, _st_erk[i].C1_Y), BN128Curve.G1Point(_st_erk[i].C2_X, _st_erk[i].C2_Y), _st_rk[i].value);
            uint[] memory _steps_C_Z = new uint[](3);
            if (i == 0) {
                _steps_C_Z[0] = _i_j_steps[2];
            } else {
                _steps_C_Z[0] = _i_j_steps[3];
            }
            _steps_C_Z[1] = C;
            _steps_C_Z[2] = _vpke_proof[i].Z;
            // g^Z == A * h^C && f(m)^C * c_1^Z == B * c_2^C
            if (!BN128Curve.g1eq(computeEq1L(_vpke_proof[i].Z), computeEq1R(BN128Curve.G1Point(_vpke_proof[i].A_X, _vpke_proof[i].A_Y), C))
                || !BN128Curve.g1eq(computeEq2L(_st_rk[i].value, _steps_C_Z, BN128Curve.G1Point(_st_erk[i].C1_X, _st_erk[i].C1_Y)), 
                computeEq2R(BN128Curve.G1Point(_vpke_proof[i].B_X, _vpke_proof[i].B_Y), BN128Curve.G1Point(_st_erk[i].C2_X, _st_erk[i].C2_Y), C))) {
                    res = false;
            }
        }
        return res;
    }
    
    function validateSig(uint _i, bytes32[] memory _c_i, bytes memory _signature_i_P) public view returns (bool){
        // Recreate chunk cipher hash
        bytes32 h = _c_i[0];
        for (uint i = 1; i < chunkLength; i++) {
            h = keccak256(abi.encodePacked(h, _c_i[i]));
        }
        // Recreate the signed message 
        bytes32 invalid_chunk = FTU.prefixed(keccak256(abi.encodePacked(_i, provider, h)));
        if (FTU.recoverSigner(invalid_chunk, _signature_i_P) == provider) {
            return true;
        } else {
            return false;
        }
    }
    
    function vrfyMTP(FTU.MerkleProof[] memory _merkleProof, bytes32 _m_i_hash) public view returns (bool) {
        bytes32 hash_temp = _m_i_hash;
        for (uint i = 0; i < _merkleProof.length; i++){
            if (_merkleProof[i].posIden == 0){
                hash_temp = keccak256(abi.encodePacked(hash_temp, _merkleProof[i].label));
            }
            if (_merkleProof[i].posIden == 1){
                hash_temp = keccak256(abi.encodePacked(_merkleProof[i].label, hash_temp));
            }
        }
        return (hash_temp == root_m);
    }
    
    function recover_chunk_key(uint _i, FTU.SubmittedRK[] memory _st_rk) public view returns (bytes32)  {
        uint x = _st_rk[0].position;
        bytes32 y =  bytes32(uint(_st_rk[0].value) | uint(_st_rk[1].value) >> 128);
        uint ind = n + _i - 2;
        if (ind < x) {
            return "";
        }
        if (ind == x) {
            return y;
        }
        // key_path_length would be > 0, otherwise ind == x and would return in the previous step
        uint key_path_length = log2_alg_floor(n) - log2_alg_floor(x+1);
        uint[] memory k_path = new uint[](key_path_length); 
        uint counter = 0;
        while (ind > x) {
            if ((ind % 2) == 0) {
                k_path[counter] = 1;
            } else {
                k_path[counter] = 0;
            }
            counter = counter + 1;
            ind = (ind - 1) / 2;
        }
        bytes32 chunk_key = y;
        for (uint i = 0; i < key_path_length; i++) {
            uint t = k_path[key_path_length - 1 - i];
            chunk_key = keccak256(abi.encodePacked(chunk_key, t));
        }
        return chunk_key;
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
    
    function validatePoM(uint[] memory _i_j_steps, bytes32[] memory _c_i, bytes memory _signature_i_P, bytes32 _m_i_hash, FTU.MerkleProof[] memory _merkleProof, FTU.SubmittedERK[] memory _st_erk, FTU.ERK[] memory _erk, FTU.SubmittedRK[] memory _st_rk, FTU.VPKEProof[] memory _vpke_proof) public view returns (bool) {
        // Only one item in KT is needed, which contains two parts and each part is 128-bit, and in total 256 bits (hash value as encryption key)
        assert((_st_erk.length == 2) && (_st_rk.length == 2) && (_vpke_proof.length == 2));
        // For the same item in KT 
        assert((_st_erk[0].position == _st_erk[1].position) && (_st_rk[0].position == _st_rk[1].position) && (_vpke_proof[0].position == _vpke_proof[1].position)
              && (_st_erk[0].position == _st_rk[0].position) && (_st_rk[0].position == _vpke_proof[0].position));
        // Ensure j (i.e., the index of erk) is in the correct range
        if (_i_j_steps[1] >= 0 && _i_j_steps[1] < _erk.length) {
            // Verify that the submitted erk is consistent with its on-chain hash
            if (check_onchain_erk(_i_j_steps[1], _st_erk, _erk)) {
                // Decryption verification
                if (verify_PKE(_i_j_steps, _st_erk, _st_rk, _vpke_proof)) {
                    // Verify signature
                    if(validateSig(_i_j_steps[0], _c_i, _signature_i_P)){
                        // Verify the merkle tree proof
                        if(vrfyMTP(_merkleProof, _m_i_hash)){
                            // Revover the chunk key based on rk and key path
                            bytes32 chunk_key = recover_chunk_key(_i_j_steps[0], _st_rk);
                            // Decrypt the chunk using the recovered chunk key
                            bytes32[chunkLength] memory decrypted_chunk = decrypt(_c_i, chunk_key);
                            // Proof of misbehavior
                            if (chunk_hash(decrypted_chunk) != _m_i_hash) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }
}

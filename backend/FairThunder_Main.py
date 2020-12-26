import os
import math
from web3 import Web3
from eth_account.messages import encode_defunct

# The number of chunks of the content m
n = 4
# The number of delivered chunks
ctr = 4
# e.g., the first chunk
invalid_chunk_index = 2

# The private master key
mk = "XXX_PRIVATE_MASTER_KEY_XXX"

infura_url = "https://ropsten.infura.io/v3/XXXXXXXXX"
web3 = Web3(Web3.HTTPProvider(infura_url))

op_contract_address = 'XXX_OPTIMISTIC_CONTRACT_ADDTRSS_XXX'
pe_contract_address = 'XXX_PESSIMISTIC_CONTRACT_ADDTRSS_XXX'

ft_provider_address = 'XXX_PROVIDER_ADDRESS_XXX'
ft_provider_private_key = 'XXX_PROVIDER_PRIVATE_KEY_XXX'

ft_consumer_address = 'XXX_CONSUMER_ADDRESS_XXX'
ft_consumer_private_key = 'XXX_CONSUMER_PRIVATE_KEY_XXX'

ft_deliverer_address = 'XXX_DELIVERER_ADDRESS_XXX'
ft_deliverer_private_key = 'XXX_DELIVERER_PRIVATE_KEY_XXX'

# chunk_size = chunk_length * 32 bytes
chunk_length = XXX
print(">> chunk length: ", chunk_length, ", chunk size(chunk length * 32 bytes): ", (chunk_length*32), " bytes, total content length: ", (chunk_length * n * 32), " bytes")


def generate_string_32_bytes():
    random_string = os.urandom(32)
    return '0x' + bytes.hex(Web3.soliditySha3(['bytes32'], [random_string]))


def generate_content(_n, _chunk_length):
    _content = ['0'] * _n
    for i in range(_n):
        _chunk = [0] * _chunk_length
        for j in range(_chunk_length):
            _chunk[j] = generate_string_32_bytes()
        _content[i] = _chunk
    return _content


def get_content_hash(_content):
    _content_hash = ['0'] * len(_content)
    for i in range(len(_content)):
        _chunk = _content[i]
        if len(_chunk) == 1:
            _chunk_temp = '0x' + bytes.hex(Web3.soliditySha3(['bytes32'], [_chunk[0]]))
        else:
            _chunk_temp = _chunk[0]
            for j in range(1, len(_chunk)):
                _chunk_temp = '0x' + bytes.hex(Web3.soliditySha3(['bytes32', 'bytes32'], [_chunk_temp, _chunk[j]]))
        _content_hash[i] = _chunk_temp
    return _content_hash


def content_encryption(_content, _key_group):
    _content_cipher = ['0'] * len(_content)
    for i in range(len(_content)):
        _chunk_cipher = ['0'] * len(_content[i])
        for j in range(len(_content[i])):
            _temp_key = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'bytes32'], [j, _key_group[i]]))
            _chunk_cipher[j] = hex(int(_temp_key, 16) ^ int(_content[i][j], 16))
        _content_cipher[i] = _chunk_cipher
    return _content_cipher


def invalid_chunk_hash(content_cipher, chunk_index):
    invalid_chunk = content_cipher[chunk_index - 1]
    h = invalid_chunk[0]
    for i in range(1, len(invalid_chunk)):
        h = bytes.hex(Web3.soliditySha3(['bytes32', 'bytes32'], [h, invalid_chunk[i]]))
    result = bytes.hex(Web3.soliditySha3(['uint256', 'address', 'bytes32'],
                                        [chunk_index, Web3.toChecksumAddress(ft_provider_address), '0x'+h]))
    return '0x' + result


def gen_sub_keys(_n, _mk):
    KT = ['0'] * (2 * _n - 1)
    KT[0] = '0x' + bytes.hex(Web3.soliditySha3(['bytes32'], [_mk]))
    for i in range(_n - 1):
        KT[2 * i + 1] = '0x' + bytes.hex(Web3.soliditySha3(['bytes32', 'uint256'], [KT[i], 0]))
        KT[2 * i + 2] = '0x' + bytes.hex(Web3.soliditySha3(['bytes32', 'uint256'], [KT[i], 1]))
    return KT


def reveal_keys(_n, _ctr, _KT):
    rk = {}
    ind = [0] * _ctr
    if _ctr == 1:
        rk.update({_n-1:KT[_n-1]})
        return rk
    for i in range(_ctr):
        ind[i] = _n - 1 + i
    while True:
        t = []
        for j in range(math.floor(len(ind)/2)):
            f_l = int((ind[2 * j] - 1) / 2)
            f_r = int((ind[2 * j + 1] - 2) / 2)
            if f_l == f_r:
                t.append(f_r)
            else:
                t.append(ind[2 * j])
                t.append(ind[2 * j + 1])
        if len(ind) % 2 != 0:
            t.append(ind[len(ind) - 1])
        if len(ind) == len(t):
            break
        ind = t
    for x in range(len(ind)):
        rk.update({ind[x]:_KT[ind[x]]})
    return rk


def build_merkle_tree(_content_hash_array):
    chunk_counter = 0
    content_length = len(_content_hash_array)
    mt_length = 2 * content_length - 1
    _MT = ['0'] * mt_length
    for i in range(mt_length - content_length, mt_length):
        _MT[i] = _content_hash_array[chunk_counter]
        chunk_counter += 1
    r_mt_index = mt_length - 1
    while r_mt_index > 0:
        temp_root = '0x' + bytes.hex(Web3.soliditySha3(['bytes32', 'bytes32'], [_MT[r_mt_index - 1], _MT[r_mt_index]]))
        target_mt_index = int(r_mt_index/2 - 1)
        _MT[target_mt_index] = temp_root
        r_mt_index -= 2
    return _MT


def generate_merkle_tree_proof(_MT, _n, _i):
    height = int(math.log2(_n))
    _MTP = ['0'] * height
    mtp_counter = 0
    index = _n - 2 + _i
    while index > 0:
        mtp_item = ['0'] * 2
        if index % 2 == 0:
            mtp_item[0] = _MT[index - 1]
            mtp_item[1] = 1
            index = int(index/2 - 1)
        else:
            mtp_item[0] = _MT[index + 1]
            mtp_item[1] = 0
            index = int((index - 1) / 2)
        _MTP[mtp_counter] = mtp_item
        mtp_counter += 1
    return _MTP


if __name__ == '__main__':
    # In FairThunder optimistic contract, the pessimistic contract address has to be checksum address
    print(">> pessimistic contract address: ", Web3.toChecksumAddress(pe_contract_address))
    KT = gen_sub_keys(n, mk)
    print('>> KT: ', KT)
    key_group = KT[len(KT) - n:len(KT)]
    print('>> sub-keys: ', key_group)

    content = generate_content(n, chunk_length)
    print('>> content: ', content)
    content_hash = get_content_hash(content)
    print('>> content_hash: ', content_hash)
    # encrypt the content (using sub-keys)
    content_cipher = content_encryption(content, key_group)
    print('>> content_cipher: ', content_cipher)

    # Build merkle tree
    MT = build_merkle_tree(content_hash)
    print('>> MT: ', MT)
    root_m = MT[0]
    print('>> root_m: ', root_m)
    MTP = generate_merkle_tree_proof(MT, n, invalid_chunk_index)
    print('>> MTP: ', MTP)
    # i is the chunk number in the receipt (i will be updated to contract as ctr)
    i = ctr
    # Generate signature for deliverer
    PoD_hash = bytes.hex(Web3.soliditySha3(['uint256', 'address', 'address', 'bytes32', 'address'],
                                           [i, Web3.toChecksumAddress(ft_consumer_address),
                                            Web3.toChecksumAddress(ft_deliverer_address),
                                            root_m, Web3.toChecksumAddress(op_contract_address)]))
    # if encode_defunct(text=PoD_hash), it will add a \n64 as the header
    PoD_message = encode_defunct(hexstr=PoD_hash)
    signature_PoD = web3.eth.account.sign_message(PoD_message, private_key=ft_deliverer_private_key)
    print(">> signature (for PoD): ", signature_PoD)

    rk = reveal_keys(n, ctr, KT)
    print('>> rk: ', rk)

    print(">> content_plain[1] (i.e., i=2): ", content[invalid_chunk_index - 1])
    print(">> content_cipher[1] (i.e., i=2): ", content_cipher[invalid_chunk_index - 1])
    invalid_chk_hash = invalid_chunk_hash(content_cipher, invalid_chunk_index)
    print(">> invalid_chunk_hash (i.e., _m_i_hash): ", invalid_chk_hash)
    invalid_chunk_message = encode_defunct(hexstr=invalid_chk_hash)
    signature_invalid_chk = web3.eth.account.sign_message(invalid_chunk_message, private_key=ft_provider_private_key)
    print(">> signature (for PoM): ", signature_invalid_chk)

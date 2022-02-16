import os
import math
from web3 import Web3
from eth_account.messages import encode_defunct

# ----------- FairThunder Test Code (for Streaming) ----------------

# The number of chunks of the content m
n = XXX
# The number of delivered chunks
ctr = XXX
# The start index (1-indexed) of request content
a = XXX
# e.g., the second chunk is invalid
invalid_chunk_index = 2

# The private master key
mk = "XXX_PRIVATE_MASTER_KEY_XXX"

infura_url = "https://ropsten.infura.io/v3/XXXXXXXXXX"
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

print(">> chunk length: ", chunk_length, ", chunk size(chunk length * 32 bytes): ", (chunk_length*32), " bytes, total content length: ", (chunk_length*n*32), " bytes")


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
            # Xor may remove 0 of most significant bits if result is not 64 characters
            _chunk_cipher[j] = "{0:#0{1}x}".format(int(_temp_key, 16) ^ int(_content[i][j], 16), 66)
        _content_cipher[i] = _chunk_cipher
    return _content_cipher


def invalid_chunk_hash(content_cipher, chunk_index):
    invalid_chunk = content_cipher[chunk_index - 1]
    # print("invalid chunk: ", invalid_chunk)
    h = invalid_chunk[0]
    if (len(invalid_chunk) == 1):
        h = '0x' + bytes.hex(Web3.soliditySha3(['bytes32'], [h]))
    else:
        for i in range(1, len(invalid_chunk)):
            h = '0x' + bytes.hex(Web3.soliditySha3(['bytes32', 'bytes32'], [h, invalid_chunk[i]]))
    result = bytes.hex(Web3.soliditySha3(['uint256', 'bytes32'], [chunk_index, h]))
    return '0x' + result


def gen_sub_keys(_n, _mk):
    KT = ['0'] * (2 * _n - 1)
    KT[0] = '0x' + bytes.hex(Web3.soliditySha3(['bytes32'], [_mk]))
    for i in range(_n - 1):
        KT[2 * i + 1] = '0x' + bytes.hex(Web3.soliditySha3(['bytes32', 'uint256'], [KT[i], 0]))
        KT[2 * i + 2] = '0x' + bytes.hex(Web3.soliditySha3(['bytes32', 'uint256'], [KT[i], 1]))
    return KT


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
    print('>> merkle tree proof (MTP): ', MTP)

    # i is the chunk number in the receipt ((i-a+1) will be updated to contract as ctr)
    i = XXX

    # Generate the signature (in receipt) for deliverer
    deliverer_receipt_hash = bytes.hex(Web3.soliditySha3(['bytes', 'uint256', 'address', 'address', 'bytes32', 'address'],
                                           ["chunkReceipt".encode('utf-8'), i, Web3.toChecksumAddress(ft_consumer_address),
                                            Web3.toChecksumAddress(ft_deliverer_address), root_m, Web3.toChecksumAddress(op_contract_address)]))
    message_CD = encode_defunct(hexstr=deliverer_receipt_hash)
    signature_CD = web3.eth.account.sign_message(message_CD, private_key=ft_consumer_private_key)
    print(">> signature_CD (for deliverer's receipt): ", signature_CD)

    # Generate the signature (in receipt) for provider
    provider_receipt_hash = bytes.hex(Web3.soliditySha3(['bytes', 'uint256', 'address', 'address', 'bytes32', 'address'],
                                          ["keyReceipt".encode('utf-8'), i, Web3.toChecksumAddress(ft_consumer_address),
                                           Web3.toChecksumAddress(ft_provider_address), root_m, Web3.toChecksumAddress(op_contract_address)]))
    message_CP = encode_defunct(hexstr=provider_receipt_hash)
    signature_CP = web3.eth.account.sign_message(message_CP, private_key=ft_consumer_private_key)
    print(">> signature_CP (for provider's receipt): ", signature_CP)
    
    # The i-th chunk that is encrypted and signed by the provider
    print(">> content_cipher[1] (i.e., i=2): ", content_cipher[invalid_chunk_index - 1])
    c_i_hash = invalid_chunk_hash(content_cipher, invalid_chunk_index)
    invalid_chunk_message = encode_defunct(hexstr=c_i_hash)
    signature_invalid_chk = web3.eth.account.sign_message(invalid_chunk_message, private_key=ft_provider_private_key)
    print(">> _c_i signature (PoM): ", signature_invalid_chk)

    # The i-th leaf node in MT
    print(">> _m_i_hash: ", content_hash[invalid_chunk_index - 1])

    # The provider may reveal a wrong key and sign it, which may lead to the PoM raised by the consumer
    orig_sub_key = key_group[invalid_chunk_index - 1]
    modified_sub_key = orig_sub_key.replace('a', 'b')
    print('>> modified_sub_key (namely the wrong _k_i): ', modified_sub_key)
    i_subkey_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'bytes32'], [invalid_chunk_index, modified_sub_key]))
    invalid_subkey_message = encode_defunct(hexstr=i_subkey_hash)
    signature_invalid_key = web3.eth.account.sign_message(invalid_subkey_message, private_key=ft_provider_private_key)
    print(">> _k_i signature (PoM): ", signature_invalid_key)


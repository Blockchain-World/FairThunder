from random import randint
from py_ecc.bn128 import G1, add, multiply, curve_order, neg
from py_ecc.bn128.bn128_field_elements import inv, field_modulus, FQ
from web3 import Web3

# ---------- FairThunder Verifiable Decryption (for Downloading) ---------

# Use BN128 curve
g = G1
p = field_modulus
rands = lambda: randint(1, p - 1)
# addmodp = lambda x, y: (x + y) % field_modulus
# submodp = lambda x, y: (x - y) % field_modulus
# mulmodp = lambda x, y: (x * y) % field_modulus
# invmodp = lambda x: inv(x, field_modulus)
# addmodn = lambda x, y: (x + y) % curve_order

# Parameter for Koblitz's algorithm, the failure ratio: 1/2^K
K = 128


# Legendre symbol
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)


# Tonelli–Shanks Algorithm: find a square root of n modulo p
def tonelli_shanks(n, p):
    # Step 0: check that n is indeed a square: (n|p) == 1
    if legendre(n, p) != 1:
        print("not a square (mod p)")
        return
    q = p - 1
    s = 0
    z = 2
    # Step 1: q is an odd number
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        # i.e., p == 3 (mod 4), output two solutions +/- n^((p+1)/4)
        return pow(n, (p + 1) // 4, p)
    # Step 2: select a non-square z such as (z | p) = -1, and set c = z^q
    for i in range(2, p):
        if p - 1 == legendre(i, p):
            z = i
            break
    c = pow(z, q, p)
    # Step 3: set r = n^((q+1)/2), t = n^q, m = s
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    # Step 4: Loop
    while True:
        i = 1
        if (t % p) == 0:
            return 0
        if (t - 1) % p == 0:
            break
        t2 = (t * t) % p
        while (t2 != 1) and (i < m):
            if (t2 - 1) % p == 0:
                break
            i += 1
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r


# Koblitz's algorithm: encoding message to point in G
def encode_message(m):
    x = 0
    y = 0
    m_int = int(m, 16)
    start = m_int * K
    for i in range(1, K):
        x = start + i
        n = x**3 + 3
        y = tonelli_shanks(n, p)
        if y is not None:
            if (y * y - n) % p == 0:
                print(">> step is: ", i)
                break
    return None if (x == 0 or y == 0) else (FQ(x), FQ(y))


# Encrypt revealed keys
def VEnc(rk, h):
    erk = {}
    for rk_key, rk_value in rk.items():
        r = rands()
        s = multiply(h, r)
        c1 = multiply(g, r)
        m_encoded = encode_message(rk_value)
        c2 = add(m_encoded, s)
        erk.update({rk_key: (c1, c2)})
    return erk


def decode_message(m_encoded):
    x = m_encoded[0].n
    # x // K will remove the i added in m*K, and only left m
    m_plain = x // K
    return m_plain


def VDec(c, k):
    decrypted_result = {}
    for erk_key, erk_value in c.items():
        c1, c2 = erk_value
        s = multiply(c1, k)
        # Pm = c2 - s
        m_encoded = add(c2, neg(s))
        m_plain = decode_message(m_encoded)
        decrypted_result.update({erk_key: hex(m_plain)[2:]})
    return decrypted_result


def prove_PKE(cipher, sk, h):
    proof = {}
    m = VDec(cipher, sk)
    for rk_key, rk_value in cipher.items():
        c1, c2 = rk_value
        print("----------------- start of ", rk_key, "------------------")
        print('>> c1: ', c1)
        print('>> c2: ', c2)
        x = rands()
        # computes A
        A = multiply(g, x)
        print('>> A: ', A)
        B = multiply(c1, x)
        print('>> B: ', B)
        g_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'uint256'], [g[0].n, g[1].n]))
        A_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'uint256'], [A[0].n, A[1].n]))
        B_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'uint256'], [B[0].n, B[1].n]))
        h_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'uint256'], [h[0].n, h[1].n]))
        c1_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'uint256'], [c1[0].n, c1[1].n]))
        c2_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256', 'uint256'], [c2[0].n, c2[1].n]))
        m_hash = '0x' + bytes.hex(Web3.soliditySha3(['uint256'], [int(m.get(rk_key), 16)]))
        C = int.from_bytes(Web3.soliditySha3(['bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32'],
                                             [g_hash, A_hash, B_hash, h_hash, c1_hash, c2_hash, m_hash]), byteorder='big') >> 160
        Z = x + sk*C
        print('>> Z: ', Z)
        print("----------------- end of ", rk_key, "------------------")
        pi = (A, B, Z)
        proof.update({rk_key: (m.get(rk_key), pi)})
    return proof


if __name__ == "__main__":
    consumer_address = "XXX_CONSUMER_ADDRESS_XXX" # e.g., 0x941D117FBF67DC60bEDad8B7Dd786B25b3259aad
    consumer_sk = "XXX_CONSUMER_SK_XXX" # e.g., 206202743888358501302336404397197755324
    consumer_pk = multiply(g, consumer_sk)
    print('>> consumer_pk: ', consumer_pk)

    # Revealed keys
    rk = {}
    # Correct key example
    rk_full = ['0x432c9a33c55dbad4bbbe8a7317785b6d8aa45e9d0c87ef2f5a3e5526a20a6b5c']
    # An incorrect key example (i.e., modified the last digit) for testing the misbehavior of provider
    # rk_full = ['0x432c9a33c55dbad4bbbe8a7317785b6d8aa45e9d0c87ef2f5a3e5526a20a6b5d']
    for i in range(len(rk_full)):
        temp = rk_full[i][2:]
        for j in range(int(2)):
            rk.update({(str(i+1) + '-' + str(j)): temp[(32 * j):(32 * (j + 1))]})
    print('>> rk: ', rk)

    # Encrypt rk as erk using the consumer's public key
    erk = VEnc(rk, consumer_pk)
    print(">> erk: ", erk)

    # Test decryption
    plain = VDec(erk, consumer_sk)
    print(">>> Decrypt erk, plain: ", plain)

    proof = prove_PKE(erk, consumer_sk, consumer_pk)
    print(">> VPKE proof: ", proof)


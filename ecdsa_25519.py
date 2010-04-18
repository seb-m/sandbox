""" 04/18/2010
ECDSA signature scheme over a twisted Edwards curve birationally equivalent
to "Curve25519" curve.

Author: Sebastien Martini (seb@dbzteam.org)
License: MIT

Requirement: Python>=3

Ways to improve this implementation:
- Implement JSF;
- Use inverted coordinates instead of projective coordinates;
- Use public key compression or another way of using only one coordinate
  as public key;
- Maybe use another variant of this ecdsa scheme, for instance one that would
  be more efficient from verifier's side or one that would provide hash
  randomization;
- Use a stronger hash algorithm and truncate its output.
"""
import hashlib
import os

def square_and_multiply_ltor(g, k, m):
    """ Left-to-right square and multiply modular exponentiation.
    /!\ Caution: Unsafe, contains sensible conditional branching and is
                 not uniform. Use only when k is not secret.
    """
    k_num_bits = k.bit_length()
    acc = 1
    while k_num_bits >= 0:
        acc = (acc ** 2) % m
        if (k >> k_num_bits) & 1:
            acc = (acc * g) % m
        k_num_bits -= 1
    return acc

def select(cond, x, y):
    """ if cond == 1 then x elif cond == 0 then y """
    return (cond - 1) & y | (-cond) & x

def mod_exp_joye_ladder(g, k, m):
    """ Return g^k mod m. Multiplicative notation.
    Implements Joye's Square-Multiply Ladder described into the followings
    papers "Highly Regular Right-to-Left Algorithms for Scalar
    Multiplication" by Marc Joye see Appendix A, algorithm 1''.
    """
    q = 1
    r = g
    while k > 0:
        cur_bit = k & 1
        b = select(cur_bit, q, r)
        sqr = b * b % m
        mul = (sqr * select(cur_bit, r, q)) % m
        q = select(cur_bit, mul, q)
        r = select(cur_bit, r, mul)
        k >>= 1
    return q

def invert(x, m, mod_exp):
    """ Invert x, returns x^-1 mod p """
    return mod_exp(x, m - 2, m)

def swap_conditional(swap, x, y):
    """
    Conditionally swap the content of integer sequences x and y inplace. x and
    y must have the same length. Elements are swapped if swap is 1 and are not
    swapped if swap is 0. swap must be 1 or 0 exclusively.
    """
    swap_mask = -swap
    for i in range(len(x)):
        swap_diff = swap_mask & (x[i] ^ y[i])
        x[i] ^= swap_diff
        y[i] ^= swap_diff

def scalar_mult_joye_ladder(n, point, id_elem, double, add):
    """
    Algorithm 1 (section 2.1) from "Highly Regular Right-to-Left Algorithms
    for Scalar Multiplication" by Marc Joye.
    """
    q = list(id_elem)
    r = list(point)
    while n > 0:
        cur_bit = n & 1
        swap_conditional(cur_bit, q, r)
        r = add(double(r), q)
        swap_conditional(cur_bit, q, r)
        n >>= 1
    return q

def double_scalar_mult_straus(k, l, p, q, id_elem, double, add):
    """
    See section 9.1.5 "Handook of Elliptic and Hyperelliptic Curve
    Cryptography" by Lange et al. This function implements algorithm 9.23
    and could be improved by implementing the JSF recoding of k and l (see
    algorithm 9.27).

    /!\ Caution: this function contains sensible conditional branching and is
                 not uniform. Use only when k and l are not secrets.
    """
    num_bits = max(k.bit_length(), l.bit_length())
    p_plus_q = add(p, q)
    acc = id_elem
    for index in range(num_bits - 1, -1, -1):
        acc = double(acc)
        b1 = (k >> index) & 1
        b2 = (l >> index) & 1
        if b1 and b2:
            acc = add(acc, p_plus_q)
        elif b1:
            acc = add(acc, p)
        elif b2:
            acc = add(acc, q)
    return acc

# Use a twisted Edwards curve with coordinates in projective
# representation as described in [1] "Twisted Edwards Curves" by Bernstein
# et al. See also http://www.hyperelliptic.org/EFD/g1p/auto-twisted.html

P = (1 << 255) - 19
# Used formulas from [1] section 3.
BASE_PT = (19682211724289367445990778417013818358151178695569199618971391691394964886553,
           46316835694926478169428394003475163141307993866256225615783033603165251855960,
           1)
Q = (1 << 252) + 27742317777372353535851937790883648493
# Used formulas from [1] section 3.
COEF_a = 486664
COEF_d = 486660
NEUTRAL_PT = (0, 1, 1)

def point_add(p, q):
    """ See [1] section 6. Return p + q """
    x1, y1, z1 = p
    x2, y2, z2 = q
    A = z1 * z2 % P
    B = A ** 2 % P
    C = x1 * x2 % P
    D = y1 * y2 % P
    E = COEF_d * C * D % P
    F = (B - E) % P
    G = (B + E) % P
    x3 = A * F * ((x1 + y1) * (x2 + y2) - C - D) % P
    y3 = A * G * (D - COEF_a * C) % P
    z3 = F * G % P
    return [x3, y3, z3]

def point_double(p):
    """ See [1] section 6. Return 2 * p """
    x1, y1, z1 = p
    B = (x1 + y1) ** 2 % P
    C = x1 ** 2 % P
    D = y1 ** 2 % P
    E = COEF_a * C % P
    F = (E + D) % P
    H = z1 ** 2 % P
    J = (F - 2 * H) % P
    x3 = (B - C - D) * J % P
    y3 = F * (E - D) % P
    z3 = F * J % P
    return [x3, y3, z3]

def point_negate(p):
    """ See [1] section 6. Return -p """
    px, py, pz = p
    return (-px % P, py, pz)

def point_is_on_curve(p):
    x, y, z = p
    x2, y2, z2 = x ** 2 % P, y ** 2 % P, z ** 2 % P
    return (COEF_a * x2 + y2) * z2 % P == (z2 ** 2 % P + COEF_d * x2 * y2) % P

def single_scalar_mult(k, p):
    """ Return k * p """
    return scalar_mult_joye_ladder(k, p, NEUTRAL_PT, point_double, point_add)

def single_scalar_mult_base(k):
    """ Return k * base """
    return single_scalar_mult(k, BASE_PT)

def double_scalar_mult(k, l, p, q):
    """ Return k*p + l*q """
    return double_scalar_mult_straus(k, l, p, q, NEUTRAL_PT, point_double,
                                     point_add)

def generate_key():
    def clamp_key(key):
        b = bytearray(key)
        b[0] &= 248;
        b[31] &= 127;
        b[31] |= 64;
        return bytes(b)
    return clamp_key(os.urandom(32))

def big_int_unpack_le(byte_seq):
    """ Unpack byte_seq bytes as a little-endian integer. """
    return sum(b << (i * 8) for i, b in enumerate(byte_seq))

def big_int_pack_le(n, n_size):
    """ Serializes integer n to little-endian bytes repr. of size n_size. """
    return bytes((n >> (i * 8)) & 0xff for i in range(0, n_size, 1))

def bytes_cmp(x, y):
    """ Compares sequences x, y. Returns True if x == y, False otherwise. """
    x_len = len(x)
    if x_len != len(y):
        return False
    different_bits = 0
    for index in range(x_len):
        different_bits |= x[index] ^ y[index]
    return different_bits == 0

def conv_proj_to_affine(p, only_x=False):
    x, y, z = p
    xinv = x * invert(z, P, square_and_multiply_ltor) % P
    yinv = None
    if not only_x:
        yinv = y * invert(z, P, square_and_multiply_ltor) % P
    return xinv, yinv

def ecdsa_keypair():
    """ Return secret_key, public_key (x || y) """
    sb = generate_key()
    si = big_int_unpack_le(sb)
    pi = single_scalar_mult_base(si)
    pix, piy = conv_proj_to_affine(pi)
    return sb, big_int_pack_le(pix, 32) + big_int_pack_le(piy, 32)

def ecdsa_sign(msg, sk):
    """ Return r || s """
    sk = big_int_unpack_le(sk)
    e = hashlib.sha256(msg).digest()
    e = big_int_unpack_le(e)
    r, s = None, None
    while True:
        k, epk = ecdsa_keypair()
        k = big_int_unpack_le(k) % Q
        # r
        r = big_int_unpack_le(epk[:32]) % Q
        if r == 0:
            continue
        # s
        s = invert(k, Q, mod_exp_joye_ladder)
        s = s * (e + r * sk) % Q
        if s == 0:
            continue
        break
    # In a "real" implementation it would be wise to somehow verify the
    # correctness of the signature before returning it.
    return big_int_pack_le(r, 32) + big_int_pack_le(s, 32)

def ecdsa_verify(msg, sig, pk):
    """ Return True is signature is valid. """
    pk = big_int_unpack_le(pk[:32]), big_int_unpack_le(pk[32:]), 1
    # Validate public key (optional step from X9.62)
    if pk == NEUTRAL_PT or (not point_is_on_curve(pk)):
        return False
    qx, qy, qz = single_scalar_mult(Q, pk)
    if qx != 0 or qy != qz:
        return False
    # Validate signature components
    r = big_int_unpack_le(sig[:32])
    s = big_int_unpack_le(sig[32:])
    for i in (r, s):
        if i < 1 or i >= Q:
            return False
    # Verify signature
    e = hashlib.sha256(msg).digest()
    e = big_int_unpack_le(e)
    w = invert(s, Q, square_and_multiply_ltor)
    u1 = e * w % Q
    u2 = r * w % Q
    rp = double_scalar_mult(u1, u2, BASE_PT, pk)
    rax, _ = conv_proj_to_affine(rp, only_x=True)
    return bytes_cmp(sig[:32], big_int_pack_le(rax % Q, 32))

if __name__ == '__main__':
    # Perform n signatures/verifications with the same private key.
    msg = b'test'
    sk, pk = ecdsa_keypair()
    loop = 100
    failures = 0
    print("Signing and verifying %s %d times:" % (msg, loop))
    for i in range(loop):
        sig = ecdsa_sign(msg, sk)
        ret = ecdsa_verify(msg, sig, pk)
        if not ret:
            failures += 1
            print("Loop %d failed" % i)
    print("Failures %d/%d" % (failures, loop))

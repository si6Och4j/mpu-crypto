import share

def gf_mult(a, b, m=1, ip=0):
    result = 0
    m_bit = 1 << m - 1
    while b > 0:
        if b & 1:
            result ^= a

        shift = a & m_bit
        a <<= 1
        if shift:
            a ^= ip

        b >>= 1

    return result

def gf_pow(a, n, m=1, ip=0):
    for _ in range(n):
        a = gf_mult(a, a, m, ip)

    return a

def gf_div(a, b):
    result = 0
    b_l = share.bin_len(b)
    while a >= b:
        n = share.bin_len(a) - b_l
        result |= 1 << n
        a ^= b << n

    return result, a

def gf_eea(a, b):
    t1 = 0
    t2 = 1
    while b > 0:
        q, b, a = *gf_div(a, b), b
        t1, t2 = t2, t1 ^ gf_mult(q, t2)

    return t1

# p - 1 от простого числа
# (p - 1) (q - 1) p, q - простые p * q - составное
# Функция Эйлера от натурального числа

import secrets

def modpow(a, n, p):
    res = 1
    while n:
        if n & 1:
            res = (a * res) % p

        # a <<= 1
        # a %= p
        a = (a * a) % p
        n >>= 1
        #print(n)

    return res

# a.k.a. Legendre symbol
def euler_criterion(a, p):
    if p == 2:
        return False

    return modpow(a, (p - 1) // 2, p)
    #return (a ** ((p - 1) // 2)) % p == 1.0

def quadratic_nonresidue(p):
    p_1 = (-1) % p
    while True:
        a = secrets.randbelow(p - 2) + 1 # 0 < a < p - 1
        c = euler_criterion(a, p)
        if c == p_1:
            return a

def get_2_pow(n):
    s = 0
    while not n & 1:
        s += 1
        n >>= 1

    return [s, n]

# Tonelli-Shanks algorithm
def ressol(n, p):
    ls = euler_criterion(n, p)
    if ls == 0:
        return [0, 0]
    elif ls != 1:
        return []

    s, Q = get_2_pow(p - 1)
    if s == 1:
        R = n ** ((p + 1) // 4)
        return [int(R) % p, int(-R) % p]

    z = quadratic_nonresidue(p)

    c = modpow(z, Q, p)
    R = modpow(n, (Q + 1) // 2, p)
    t = modpow(n, Q, p)
    M = s

    while t != 1:
        for i in range(1, M):
            if modpow(t, (2 ** i) % p, p) == 1:
                b = modpow(c, modpow(2, M - i - 1, p), p)
                M = i
                break

        c = (b ** 2) % p
        t = (t * b ** 2) % p
        R = (R * b) % p

    return [int(R), int(-R) % p]

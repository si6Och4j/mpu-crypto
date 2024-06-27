import secrets
from cryprime import modpow

alphabet_ru33 = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
alphabet_ru32 = "абвгдежзийклмнопрстуфхцчшщъыьэюя"
alphabet_ru31 = "абвгдежзиклмнопрстуфхцчшщъыьэюя"
alphabet_ru30 = "абвгдежзиклмнопрстуфхцчшщьыэюя"

rules_format = {
    # ' ': 'прб',
    ' ': '',
    ';': 'тчкзпт',
    '.': 'тчк',
    ',': 'зпт',
    '-': 'тире',
}

rules_to_ru32 = {
    'ё': 'е',
    **rules_format
}

rules_to_ru31 = {
    'й': 'и',
    **rules_to_ru32,
}

rules_to_ru30 = {
    'ъ': 'ь',
    **rules_to_ru31,
}

rules_rv_format = {
    'тчкзпт': ';',
    'тчк': '.',
    'зпт': ',',
    'тире': '-',
    # 'прб': ' ',
}

def text_format(data, fmt):
    data = str(data).lower()

    for k in fmt:
        data = data.replace(k, fmt[k])

    return data

def text_to_nums(message, alphabet, shift=1):
    alphabet_list = list(alphabet)

    try:
        result = []
        for c in list(message):
            if not (isinstance(c, str) and c in alphabet_list):
                raise RuntimeError(
                    f'Unable to convert non-str value to int ({c})'
                )

            result.append(int(alphabet_list.index(c) + shift))
    except IndexError:
        return []

    return result

def nums_to_text(numbers, alphabet, shift=-1):
    alphabet_list = list(alphabet)

    try:
        result = []
        for c in list(numbers):
            if not isinstance(c, int):
                raise RuntimeError('Unable to convert non-int value')

            result.append(str(alphabet_list[c + shift]))
    except IndexError as e:
        print(e, c, ''.join(result))
        return []

    return result

def text_to_bin(message, alphabet, shift=1):
    bits_per_symbol = round(len(alphabet) ** 0.5)

    result = 0
    bits_size = 0
    for num in text_to_nums(message, alphabet, shift):
        result <<= bits_per_symbol
        result |= num

        bits_size += bits_per_symbol

    return result, bits_size

def bin_to_text(value, alphabet, shift=-1):
    bits_per_symbol = round(len(alphabet) ** 0.5)

    numbers = []
    while value > 0:
        tmp = value & ((1 << bits_per_symbol) - 1)
        numbers.append(tmp)
        value >>= bits_per_symbol

    return ''.join(nums_to_text(numbers[::-1], alphabet, shift))

def bin_len(value):
    size = 0
    value = int(value)
    while value > 0:
        size += 1
        value >>= 1

    return size

def byte_swap(data, n, step=8):
    result = 0
    for _ in range(n):
        result <<= step
        result |= data & ((1 << step) - 1)
        data >>= step

    return result

def split_blocks(data, size=32, total_size=-1):
    data = int(data)
    # if total_size < 0:
        # total_size = bin_len(data)

    result = []
    mask = (1 << size) - 1
    while True:
        if total_size > 0:
            if total_size <= size:
                result.append(data & (1 << total_size) - 1)
                break

            total_size -= size

        result.append(data & mask)
        data >>= size

        if total_size < 0 and data <= 0:
            break

    return result

def concat_blocks(data, size=32, total_size=-1):
    cnt = 0
    result = 0
    mask = (1 << size) - 1
    for i in data:
        i = int(i)
        if total_size > 0 and total_size < size:
            result |= (i & (1 << total_size) - 1) << size * cnt
            break
        else:
            result |= (i & mask) << size * cnt

        total_size -= size
        cnt += 1

    return result

def msb(data, n, size=-1):
    if size <= 0:
        size = bin_len(data)

    return data >> (size - n)

def lsb(data, n):
    return data & ((1 << n) - 1)

def circular_shift_l(data, n, m):
    return (data << n | data >> (m - n)) & ((1 << m) - 1)

def circular_shift_r(data, n, m):
    return (data << (m - n) | data >> n) & ((1 << m) - 1)


def get_prime(max_v, coprime=-1, min_v=3):
    v_range = max_v - min - 1

    #if v_range <= min_v or v_range <= 1:
    #	raise RuntimeError(f'Unable to generate prime number. Invalid range: {v_range}')

    while True:
        k = secrets.randbelow(v_range) + min_v # min_v < k < max_v
        if not is_prime(k):
            continue

        if coprime > 0 and gcd(k, coprime) != 1:
            continue

        return k

def get_prime_pool(n, max_v, coprime=-1):
    k_pool = []
    c = 0
    while c < n:
        p = get_prime(max_v, coprime)
        if p in k_pool:
            continue

        c += 1
        print(p)
        k_pool.append(p)

    return k_pool

def sq_wrap_hash(text, p, alphabet):
    h = 0
    for i in text_to_nums(text, alphabet):
        h = ((h + i) ** 2) % p

    return h

def gcd(a, b, ops=None):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    if not ops:
        ops = []

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    if len(ops) > 0:
        return [
            old_r,
            *([], [old_s])['s' in ops],
            *([], [old_t])['t' in ops]
        ]

    return old_r

def eea(a, b, p):
    r, s = gcd(a, p, ['s'])

    if r != 1:
        if b % r != 0:
            raise RuntimeError('GCD isn\'t equal 1. EEA is not possible')
            #return None	 # No solution exists if gcd(a, r) != 1

        a //= r
        b //= r
        p //= r

    # Calculate the inverse of a modulo m
    a_inv = s % p

    # Use the formula x = a_inv * b (mod p)
    return (a_inv * b) % p

# Fermat primality test
def is_prime(n):
    # Проверяем только плоские числа,
    # для остального лучше использовать тест Ферма
    for i in [2, 3, 5, 7, 11, 13, 17]:
        if n % i == 0:
            return False

    for i in range(30):
        a = secrets.randbelow(n - 2) + 1 # 1 < k < n - 1
        if modpow(a, n - 1, n) != 1:
            return False

    return True

def factorization(n, steps=-1):
    result = {}
    n1 = n

    while n1 > 1 and steps != 0:
        prime = True
        for i in [2, 3, 5, 7, 11, 13, 17]: # Проверяем только плоские числа, для остального лучше использовать тест Ферма
            if n1 % i != 0:
                continue

            if not i in result:
                result[i] = 0

            result[i] += 1
            n1 //= i
            prime = False
            break

        if steps > 0:
            steps -= 1

        if prime:
            result[n1] = 1
            break

    return result

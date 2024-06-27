import share
from cryprime import modpow

class rsa:
    _MODULE_NAME = 'RSA'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {
        'h_p': 11,
    }
    _MODULE_KEY_PARAMS = [
        ['n', 'Произведение простых чисел', int],
        ['e', 'Публичная экспонента', int],
        ['d', 'Секретная экспонента', int],
    ]
    _MODULE_KEYGEN_PARAMS = [
        ['e', 'Публичная экспонента', int],
        ['key_size', 'Размер ключа (бит)', int],
    ]

    @staticmethod
    def get_pubkey(p, q, e):
        return [e, p * q]

    @staticmethod
    def get_privkey(p, q, e):
        phi = (p - 1) * (q - 1)
        d = share.eea(e, 1, phi)

        return [d, p * q]

    @classmethod
    def keygen(cls, keygen_config):
        e = int (keygen_config['e'])
        key_size = int (keygen_config['key_size'])

        prime_size = (1 << (key_size // 2)) - 1
        while True:
            p = share.get_prime(prime_size)
            q = share.get_prime(prime_size)

            if share.bin_len(p * q) != key_size:
                continue

            prime_phi = (p - 1) * (q - 1)
            if share.gcd(e, prime_phi) == 1:
                break

        e, n = cls.get_pubkey(p, q, e)
        d, n = cls.get_privkey(p, q, e)

        return cls._MODULE_KEY_DEFAULT | {
            'e': e,
            'd': d,
            'n': n
        }

    @staticmethod
    def sign(cipher_config, message, alphabet):
        n = int(cipher_config['n'])
        d = int(cipher_config['d'])
        h_p = int(cipher_config['h_p'])

        m_h = share.sq_wrap_hash(message, h_p, alphabet)

        return modpow(m_h, d, n)

    @staticmethod
    def verify(cipher_config, message, signature, alphabet):
        n = int(cipher_config['n'])
        e = int(cipher_config['e'])
        h_p = int(cipher_config['h_p'])

        m_h = share.sq_wrap_hash(message, h_p, alphabet)

        return modpow(signature, e, n) == m_h

    @staticmethod
    def encrypt(cipher_config, message, alphabet):
        n = int(cipher_config['n'])
        e = int(cipher_config['e'])

        message, _ = share.text_to_bin(message, alphabet)
        n_len = share.bin_len(n)

        result = []
        for block in share.split_blocks(message, n_len - 1):
            result.append(modpow(block, e, n))

        r = share.concat_blocks(result, n_len)

        return r

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        n = int(cipher_config['n'])
        d = int(cipher_config['d'])
        n_len = share.bin_len(n)

        result = []
        for block in share.split_blocks(ciphertext, n_len):
            result.append(modpow(block, d, n))

        result = share.concat_blocks(result, n_len - 1)

        return share.bin_to_text(result, alphabet)

rsa._MODULE_CAPABILITIES = {
    'enc': rsa.encrypt,
    'dec': rsa.decrypt,
    'sig': rsa.sign,
    'ver': rsa.verify,
    'kyg': rsa.keygen,
}

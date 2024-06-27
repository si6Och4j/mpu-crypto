import secrets
import share
from cryprime import modpow

class elgamal:
    _MODULE_NAME = 'ElGamal'
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
        ['p', 'Случайное простое число', int],
        ['g', 'Первообразный корень p', int],
        ['x', 'Секретная экспонента', int],
        ['y', 'Публичная экспонента', int],
    ]
    _MODULE_KEYGEN_PARAMS = [
        ['key_size', 'Размер ключа (бит)', int],
    ]

    @staticmethod
    def get_pubkey(g, x, p):
        y = modpow(g, x, p)

        return [g, y, p]

    @classmethod
    def keygen(cls, keygen_config):
        prime_size = (1 << int(keygen_config['key_size'])) - 1

        p = share.get_prime(prime_size)
        phi = p - 1

        # g должен быть первообразным корнем
        g = share.get_prime(prime_size, p)
        while modpow(g, phi // 2, p) == 1:
            g = share.get_prime(prime_size, p)

        x = secrets.randbelow(phi - 2) + 2 # 1 < x < phi
        g, y, p = cls.get_pubkey(g, x, p)

        return cls._MODULE_KEY_DEFAULT | {
            'g': g,
            'x': x,
            'y': y,
            'p': p,
        }

    @staticmethod
    def sign(cipher_config, message, alphabet):
        p = int(cipher_config['p'])
        g = int(cipher_config['g'])
        x = int(cipher_config['x'])
        h_p = int(cipher_config['h_p'])

        m_h = share.sq_wrap_hash(message, h_p, alphabet)
        phi = p - 1

        while True:
            k = share.get_prime(phi)
            a = modpow(g, k, p)
            if a == 0:
                continue

            # Альтернативный способ
            #k_1 = share.eea(k, 1, phi_p)
            #b = ((m_h - x * a) * k_1) % phi_p
            try:
                b = share.eea(k, (m_h - x * a), phi)
            except Exception:
                continue

            break

        return share.concat_blocks([a, b], share.bin_len(p))

    @staticmethod
    def verify(cipher_config, message, signature, alphabet):
        p = int(cipher_config['p'])
        g = int(cipher_config['g'])
        y = int(cipher_config['y'])
        h_p = int(cipher_config['h_p'])

        m_h = share.sq_wrap_hash(message, h_p, alphabet)
        a, b = share.split_blocks(signature, share.bin_len(p))

        # Альтернативный способ
        #return share.eea(g ** m_h, (y ** a) * (a ** b), p)
        y1 = modpow(g, m_h, p)
        y2 = (modpow(y, a, p) * modpow(a, b, p)) % p

        return y1 == y2

    @staticmethod
    def encrypt(cipher_config, message, alphabet):
        p = int(cipher_config['p'])
        g = int(cipher_config['g'])
        y = int(cipher_config['y'])

        message, _ = share.text_to_bin(message, alphabet)
        p_len = share.bin_len(p)
        phi = p - 1

        result = []
        for block in share.split_blocks(message, p_len - 1):
            while True:
                k = share.get_prime(p, phi)
                a = modpow(g, k, p)
                if a == 0:
                    continue

                b = (modpow(y, k, p) * block) % p
                if b == 0:
                    continue

                break

            result.append(a)
            result.append(b)

        return share.concat_blocks(result, p_len)

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        p = int(cipher_config['p'])
        x = int(cipher_config['x'])
        p_len = share.bin_len(p)

        blocks = share.split_blocks(ciphertext, p_len)
        blocks_len = len(blocks)

        result = []
        while blocks_len > 0:
            a = blocks.pop(0)
            b = blocks.pop(0)
            blocks_len -= 2

            result.append(share.eea(modpow(a, x, p), b, p))

        result = share.concat_blocks(result, p_len - 1)

        return share.bin_to_text(result, alphabet)

elgamal._MODULE_CAPABILITIES = {
    'enc': elgamal.encrypt,
    'dec': elgamal.decrypt,
    'sig': elgamal.sign,
    'ver': elgamal.verify,
    'kyg': elgamal.keygen,
}

import secrets
import sys
import share
from ecc import ECC

sys.set_int_max_str_digits(100000)

class ecc_elgamal:
    _MODULE_NAME = 'ElGamal ECC'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['g_x', 'Координата X точки генератора ЭК', int],
        ['g_y', 'Координата Y точки генератора ЭК', int],
        ['d_x', 'Координата X точки ключа ЭК', int],
        ['d_y', 'Координата Y точки ключа ЭК', int],
        ['a', 'Коэффициент a', int],
        ['b', 'Коэффициент b', int],
        ['p', 'Модуль ЭК', int],
        ['q', 'Порядок подгруппы точек ЭК', int],
        ['c', 'Секретный ключ', int],
    ]
    _MODULE_KEYGEN_PARAMS = [
        ['x', 'Координата X точки ЭК', int],
        ['y', 'Координата Y точки ЭК', int],
        ['a', 'Коэффициент a', int],
        ['b', 'Коэффициент b', int],
        ['p', 'Модуль ЭК', int],
        ['q', 'Порядок подгруппы точек ЭК', int],
    ]

    @staticmethod
    def get_pubkey(G, c):
        return ECC.from_object(G)[c]

    @classmethod
    def keygen(cls, keygen_config):
        G = ECC.from_object(keygen_config)

        c = secrets.randbelow(G.q - 1) + 1 # 0 < c < q
        D = cls.get_pubkey(G, c)

        return {
            'g_x': G.x,
            'g_y': G.y,
            'd_x': D.x,
            'd_y': D.y,
            'a': G.a,
            'b': G.b,
            'p': G.p,
            'q': G.q,
            'c': c,
        }

    @staticmethod
    def encrypt(cipher_config, message, alphabet):
        G = ECC.from_object({
            'x': cipher_config['g_x'],
            'y': cipher_config['g_y'],
        } | cipher_config)
        D = ECC.from_object({
            'x': cipher_config['d_x'],
            'y': cipher_config['d_y'],
        } | cipher_config)
        # c = cipher_config['c']
        phi_p = G.p - 1

        message, _ = share.text_to_bin(message, alphabet)
        p_len = share.bin_len(G.p)

        result = []
        for block in share.split_blocks(message, p_len - 1):
            k = share.get_prime(G.q + 1, phi_p) - 1

            R = G[k]
            result.append(R.x)
            result.append(R.y)
            result.append((block * D[k].x) % G.p)

        return share.concat_blocks(result, p_len)

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        G = ECC.from_object({
            'x': cipher_config['g_x'],
            'y': cipher_config['g_y'],
        } | cipher_config)
        c = cipher_config['c']
        p_len = share.bin_len(G.p)

        blocks = share.split_blocks(ciphertext, p_len)
        blocks_len = len(blocks)

        result = []
        try:
            while blocks_len > 0:
                Rx = blocks.pop(0)
                Ry = blocks.pop(0)
                e = blocks.pop(0)
                blocks_len -= 3

                Q = G.get_clone(Rx, Ry)[c]
                m = share.eea(Q.x, e, Q.p)

                result.append(m)
        except Exception:
            print('Unable to decrypt message')
            return ''

        result = share.concat_blocks(result, p_len - 1)

        return share.bin_to_text(result, alphabet)

ecc_elgamal._MODULE_CAPABILITIES = {
    'enc': ecc_elgamal.encrypt,
    'dec': ecc_elgamal.decrypt,
    'kyg': ecc_elgamal.keygen,
}

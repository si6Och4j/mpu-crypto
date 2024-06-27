import secrets
from ecc import ECC
import share
from cryprime import modpow
from t26_gost_34_10_94_lcg import LCG

class gost_34_10:
    class s94:
        _MODULE_NAME = 'ГОСТ Р 34.10-94'
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
            ['p', 'Публичный параметр p', int],
            ['q', 'Публичный параметр q', int],
            ['a', 'Публичный параметр a', int],
            ['x', 'Секретный ключ', int],
            ['y', 'Открытый ключ', int],
        ]
        _MODULE_KEYGEN_PARAMS = [
            ['key_size', 'размер ключа (бит)', int]
        ]

        @staticmethod
        def get_pubkey(a, x, p):
            return modpow(a, x, p)

        @classmethod
        def keygen(cls, keygen_config):
            gen_primes = LCG.b512.gen(
                int(keygen_config['key_size']),
                0x5EC9,
                0x7341
            )
            p = gen_primes[0]
            q = gen_primes[1]

            while True:
                a = modpow(secrets.randbelow(p - 2) + 1, (p - 1) // q, p)
                if a > 1:
                    break

            x = secrets.randbelow(p - 2) + 1
            y = cls.get_pubkey(a, x, p)

            return cls._MODULE_KEY_DEFAULT | {
                'p': p,
                'q': q,
                'a': a,
                'x': x,
                'y': y,
            }

        @staticmethod
        def sign(cipher_config, message, alphabet):
            p = int(cipher_config['p'])
            q = int(cipher_config['q'])
            a = int(cipher_config['a'])
            x = int(cipher_config['x'])
            h_p = int(cipher_config['h_p'])
            # phi_q = share.bin_len(q)

            m_h = share.sq_wrap_hash(message, h_p, alphabet)
            if m_h % q == 0:
                m_h = 1

            while True:
                # Почему-то с простыми числами всё разваливается
                # Особо это заметно на малых значениях
                k = secrets.randbelow(q + 1) - 1
                if k <= 0:
                    continue

                r = modpow(a, k, p) % q
                if r == 0:
                    continue

                s = (x * r + k * m_h) % q
                if s == 0:
                    continue

                print(r, s)

                break

            return share.concat_blocks([r, s], share.bin_len(q))

        @staticmethod
        def verify(cipher_config, message, signature, alphabet):
            p = int(cipher_config['p'])
            q = int(cipher_config['q'])
            a = int(cipher_config['a'])
            y = int(cipher_config['y'])
            h_p = int(cipher_config['h_p'])

            r, s = share.split_blocks(signature, share.bin_len(q))
            if r >= q or s >= q:
                return False

            m_h = share.sq_wrap_hash(message, h_p, alphabet)
            if m_h % q == 0:
                m_h = 1

            v = modpow(m_h, q - 2, q)
            z1 = (s * v) % q
            z2 = ((q - r) * v) % q
            u = ((modpow(a, z1, p) * modpow(y, z2, p)) % p) % q

            return r == u

    s94._MODULE_CAPABILITIES = {
        'sig': s94.sign,
        'ver': s94.verify,
        'kyg': s94.keygen,
    }


    class s2012:
        _MODULE_NAME = 'ГОСТ Р 34.10-2012'
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
            ['g_x', 'Координата X точки генератора ЭК', int],
            ['g_y', 'Координата Y точки генератора ЭК', int],
            ['q_x', 'Координата X точки ключа ЭК', int],
            ['q_y', 'Координата Y точки ключа ЭК', int],
            ['a', 'Коэффициент a', int],
            ['b', 'Коэффициент b', int],
            ['p', 'Модуль ЭК', int],
            ['q', 'Порядок подгруппы точек ЭК', int],
            ['d', 'Секретный ключ', int],
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
        def get_pubkey(G, d):
            return ECC.from_object(G)[d]

        @classmethod
        def keygen(cls, keygen_config):
            G = ECC.from_object(keygen_config)

            d = secrets.randbelow(G.q - 1) + 1 # 1 < d < q
            Q = cls.get_pubkey(G, d)

            return cls._MODULE_KEY_DEFAULT | {
                'g_x': G.x,
                'g_y': G.y,
                'q_x': Q.x,
                'q_y': Q.y,
                'a': G.a,
                'b': G.b,
                'p': G.p,
                'q': G.q,
                'd': d,
            }

        @staticmethod
        def sign(cipher_config, message, alphabet):
            G = ECC.from_object({
                'x': cipher_config['g_x'],
                'y': cipher_config['g_y'],
            } | cipher_config)
            d = int(cipher_config['d'])
            h_p = int(cipher_config['h_p'])

            m_h = share.sq_wrap_hash(message, h_p, alphabet)
            if m_h % G.q == 0:
                m_h = 1

            while True:
                k = secrets.randbelow(G.q - 1) + 1
                P = G[k]

                r = P.x % G.q
                if r == 0:
                    continue

                s = (k * m_h + r * d) % G.q
                if s == 0:
                    continue

                break

            return share.concat_blocks([r, s], share.bin_len(G.q))

        @staticmethod
        def verify(cipher_config, message, signature, alphabet):
            G = ECC.from_object({
                'x': cipher_config['g_x'],
                'y': cipher_config['g_y'],
            } | cipher_config)
            Q = ECC.from_object({
                'x': cipher_config['q_x'],
                'y': cipher_config['q_y'],
            } | cipher_config)
            h_p = int(cipher_config['h_p'])

            r, s = share.split_blocks(signature, share.bin_len(G.q))
            if r > G.q or s > G.q:
                return False

            m_h = share.sq_wrap_hash(message, h_p, alphabet)
            if m_h % G.q == 0:
                m_h = 1

            try:
                u1 = share.eea(m_h, s, G.q)
                u2 = share.eea(m_h, -r, G.q)
                P = G[u1] + Q[u2]
            except Exception:
                print('Unable to verify message')
                return False

            return P.x % G.q == r

    s2012._MODULE_CAPABILITIES = {
        'sig': s2012.sign,
        'ver': s2012.verify,
        'kyg': s2012.keygen,
    }

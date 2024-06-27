import secrets
import share
from cryprime import modpow

class diffie_hellman_ke:
    _MODULE_NAME = 'Обмен ключами Diffie-Hellman'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['g', 'Публичный параметр g', int],
        ['p', 'Публичный параметр p', int],
    ]
    _MODULE_KEYGEN_PARAMS = [
        ['key_size', 'размер ключа (бит)', int]
    ]

    @staticmethod
    def keygen(keygen_config):
        prime_size = (1 << int(keygen_config['key_size'])) - 1

        p = share.get_prime(prime_size)
        phi = p - 1

        # g должен быть первообразным корнем
        g = share.get_prime(prime_size, p)
        while modpow(g, phi // 2, p) == 1:
            g = share.get_prime(prime_size, p)

        return {
            'g': g,
            'p': p,
        }

    @staticmethod
    def create(cipher_config):
        g = int(cipher_config['g'])
        p = int(cipher_config['p'])

        x = secrets.randbelow(p - 4) + 3 # 2 < x < p-1
        y = modpow(g, x, p)

        return x, y

    @staticmethod
    def exchange(cipher_config, data, key):
        return modpow(data, key, int(cipher_config['p']))

diffie_hellman_ke._MODULE_CAPABILITIES = {
    'kec': diffie_hellman_ke.create,
    'kee': diffie_hellman_ke.exchange,
    'kyg': diffie_hellman_ke.keygen,
}

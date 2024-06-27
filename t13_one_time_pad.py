import share

class one_time_pad:
    _MODULE_NAME = 'Одноразовый блокнот К.Шеннона'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['t0', 'Исходное состояние генератора', int],
        ['a', 'Взаимно простой с m, множитель', int],
        ['c', 'Взаимно простое с a, слагаемое', int],
    ]
    _MODULE_KEYGEN_PARAMS = [
        ['key_size', 'Размер ключа (бит)', int],
    ]

    @staticmethod
    def keygen(key_size, p):
        max_key_value = (1 << key_size) - 1

        a = share.get_prime(max_key_value)
        while (a - 1) % p:
            a = share.get_prime(max_key_value)

        c = share.get_prime(max_key_value, a)

        return [a, c]

    @staticmethod
    def _gamma_generator(cipher_config):
        t0 = int(cipher_config['t0'])
        a = int(cipher_config['a'])
        c = int(cipher_config['c'])
        m = int(cipher_config['m'])

        while True:
            t0 = (a * t0 + c) % m

            yield t0

    @classmethod
    def process(cls, cipher_config, data, alphabet):
        n = len(alphabet)
        # Set the value of 'm' in the cipher
        # configuration as the length of the alphabet
        cipher_config['m'] = n

        result = []
        # Initialize gamma generator
        generator = cls._gamma_generator(cipher_config)
        # Convert data into a list of numbers based on the given alphabet
        for m in share.text_to_nums(data, alphabet):
            # XOR each character with the next key generated from gamma
            # generator and take modulo n
            result.append((m ^ next(generator)) % n)

        return ''.join(share.nums_to_text(result, alphabet))

one_time_pad._MODULE_CAPABILITIES = {
    'enc': one_time_pad.process,
    'dec': one_time_pad.process,
}

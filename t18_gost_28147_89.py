import share
from t07_gost_r_34_12 import magma

class gost_28147_89:
    # Таблица замены из ГОСТ Р 34.11-94
    _s_box = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
    ]

    @classmethod
    def _encrypt_block(cls, key, data):
        # Changing bytes endiannes
        key = share.byte_swap(key, 8, 32)

        # Performing all rounds using GOST 28147-89 S-Box
        return magma._all_rounds(
            magma._key_shedule(key),
            data,
            gost_28147_89._s_box
        )

    @classmethod
    def _decrypt_block(cls, key, data):
        # Changing bytes endiannes
        key = share.byte_swap(key, 8, 32)

        # Performing all rounds using GOST 28147-89 S-Box
        return magma._all_rounds(
            magma._key_shedule(key)[::-1],
            data,
            gost_28147_89._s_box
        )

    class ECB:
        @staticmethod
        def encrypt(key, message, size=-1):
            result = []
            for data in share.split_blocks(message, 64, size):
                result.append(gost_28147_89._encrypt_block(key, data))

            return share.concat_blocks(result, 64, size)

        @staticmethod
        def decrypt(key, ciphertext, size=-1):
            result = []
            for data in share.split_blocks(ciphertext, 64, size):
                result.append(gost_28147_89._decrypt_block(key, data))

            return share.concat_blocks(result, 64, size)


    class ECB_wrap:
        _MODULE_NAME = 'ГОСТ 28147-89 Режим ECB'
        _MODULE_DEFAULT_ALPHABET_SET = {
            'a': share.alphabet_ru32,
            'to': share.rules_to_ru32,
            'from': share.rules_rv_format
        }
        _MODULE_CAPABILITIES = {}
        _MODULE_KEY_DEFAULT = {}
        _MODULE_KEY_PARAMS = [
            ['key', 'Ключ', int]
        ]

        @staticmethod
        def encrypt(cipher_config, message, alphabet):
            message, _ = share.text_to_bin(message, alphabet)

            return gost_28147_89.ECB.encrypt(cipher_config['key'], message)

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet):
            result = gost_28147_89.ECB.decrypt(cipher_config['key'], ciphertext)

            return share.bin_to_text(result, alphabet)

    ECB_wrap._MODULE_CAPABILITIES = {
        'enc': ECB_wrap.encrypt,
        'dec': ECB_wrap.decrypt,
    }

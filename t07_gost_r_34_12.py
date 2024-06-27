import share
from galois_field import gf_mult

# Длина блока(n) - 64 бита (Выборка всех битов блока - 0xffffffffffffffff)
class magma:
    _s_box = [
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
    ]

    @staticmethod
    def _t_transform(data, s_box):
        result = 0
        for i in range(8):
            # Performs substitution operation on per block basis
            result |= s_box[i][data & 15] << (i * 4)
            data >>= 4
        return result

    @staticmethod
    def _t_transform_r(data, s_box):
        result = 0
        for i in range(8):
            # Performs substitution operation on per block basis
            result |= s_box[i].index(data & 15) << (i * 4)
            data >>= 4

        return result

    @classmethod
    def _g_transform(cls, data, key, s_box):
        # Perform right-to-left bitwise XOR between input data and key,
        # then perform _t_transform using the result
        data = (data + key) & 0xffffffff
        data = cls._t_transform(data, s_box)

        # Shift the resulting data left by 11 bits in a
        # circular manner within a 32-bit word
        data = share.circular_shift_l(data, 11, 32)

        return data

    @classmethod
    def _g_transform_r(cls, data, key, s_box):
        # Shift the input data right by 11 bits in a
        # circular manner within a 32-bit word
        data = share.circular_shift_r(data, 11, 32)

        # Perform _t_transform operation on the
        # right-shifted data and subtract the key from the result
        data = cls._t_transform_r(data, s_box) - key

        # Return the transformed data
        return data

    class P_box:
        _MODULE_NAME = 'ГОСТ Р 34.12-2015 P-Блок'
        _MODULE_DEFAULT_ALPHABET_SET = {
            'a': share.alphabet_ru32,
            'to': share.rules_to_ru32,
            'from': share.rules_rv_format
        }
        _MODULE_CAPABILITIES = {}
        _MODULE_KEY_DEFAULT = {}
        _MODULE_KEY_PARAMS = []

        @staticmethod
        def encrypt(cipher_config, message, alphabet, size=-1):
            key = int(cipher_config['key'])
            # Convert the input message text to binary format
            # using the given alphabet
            message, _ = share.text_to_bin(message, alphabet)

            result = []
            # Split the binary message into blocks of 32 bits
            for block in share.split_blocks(message, 32, size):
                # Apply Magma's _g_transform function to each block
                # using the given key and s-box
                result.append(magma._g_transform(block, key, magma._s_box))

            return share.concat_blocks(result, 32, size)

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet, size=-1):
            key = int(cipher_config['key'])
            result = []
            # Split the given ciphertext into blocks based on the given size
            for block in share.split_blocks(ciphertext, 32, size):
                # Perform decryption operation on each block
                # using the provided key and _s_box.
                result.append(magma._g_transform_r(block, key, magma._s_box))

            result = share.concat_blocks(result, 32, size)

            return share.bin_to_text(result, alphabet)

    P_box._MODULE_CAPABILITIES = {
        'enc': P_box.encrypt,
        'dec': P_box.decrypt,
    }


    class S_box:
        _MODULE_NAME = 'ГОСТ Р 34.12-2015 S-Блок'
        _MODULE_DEFAULT_ALPHABET_SET = {
            'a': share.alphabet_ru32,
            'to': share.rules_to_ru32,
            'from': share.rules_rv_format
        }
        _MODULE_CAPABILITIES = {}
        _MODULE_KEY_DEFAULT = {}
        _MODULE_KEY_PARAMS = []

        @staticmethod
        def encrypt(cipher_config, message, alphabet, size=-1):
            # Convert text message to binary format using the provided alphabet
            message, _ = share.text_to_bin(message, alphabet)

            result = []
            # Apply Encryption to each block using the provided _s_box
            for data in share.split_blocks(message, 32, size):
                result.append(magma._t_transform(data, magma._s_box))

            # Concatenate the encrypted blocks back into a single binary message
            return share.concat_blocks(result, 32, size)

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet, size=-1):
            result = []
            # Convert encrypted binary data to individual
            for data in share.split_blocks(ciphertext, 32, size):
                # Decrypt each block using the provided S-box
                # and add it to the result list
                result.append(magma._t_transform_r(data, magma._s_box))

            # Concatenate the encrypted blocks back into a single message
            result = share.concat_blocks(result, 32, size)

            return share.bin_to_text(result, alphabet)

    S_box._MODULE_CAPABILITIES = {
        'enc': S_box.encrypt,
        'dec': S_box.decrypt,
    }


    @staticmethod
    def _key_shedule(key):
        result = []
        ranges = [
            range(7, -1, -1),
            range(7, -1, -1),
            range(7, -1, -1),
            range(8)
        ]

        # Loop through each range in the list
        for r in ranges:
            # For each iteration in the current range
            for i in r:
                # Append the right-shifted bitwise AND of
                # key and 0xffffffff to result
                result.append((key >> (i * 32)) & 0xffffffff)

        # Return the generated list as result
        return result

    @classmethod
    def _round(cls, key, a1, a0, s_box):
        """Performs a single round of encryption or decryption."""
        result = cls._g_transform(a0, key, s_box)
        return [a0, a1 ^ result]

    @classmethod
    def _all_rounds(cls, keys, data, s_box):
        """Performs all required rounds of encryption or decryption."""
        a0, a1 = share.split_blocks(data, 32, 64)

        for index in range(32):
            a1, a0 = cls._round(keys[index], a1, a0, s_box)

        return (a0 << 32) | a1

    @classmethod
    def _encrypt_block(cls, key, data):
        """Encrypts the given block using provided key."""
        return cls._all_rounds(cls._key_shedule(key), data, cls._s_box)

    # Class method for decrypting a single block
    @classmethod
    def _decrypt_block(cls, key, data):
        """Decrypts the given block using provided key."""
        return cls._all_rounds(cls._key_shedule(key)[::-1], data, cls._s_box)

    class ECB:
        @staticmethod
        def encrypt(key, message, size=-1):
            result = []
            # Split the given message into 64-bit blocks.
            for block in share.split_blocks(message, 64, size):
                # Encrypt each block using Magma's encryption
                # function with the given key.
                result.append(magma._encrypt_block(key, block))

            return share.concat_blocks(result, 64, size)

        @staticmethod
        def decrypt(key, ciphertext, size=-1):
            result = []
            # Split the given message into 64-bit blocks.
            for block in share.split_blocks(ciphertext, 64, size):
                # Decrypt each block using Magma's encryption
                # function with the given key.
                result.append(magma._decrypt_block(key, block))

            return share.concat_blocks(result, 64, size)


    class ECB_wrap:
        _MODULE_NAME = 'ГОСТ Р 34.12-2015 Режим ECB'
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

            return magma.ECB.encrypt(cipher_config['key'], message)

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet):
            result = magma.ECB.decrypt(cipher_config['key'], ciphertext)

            return share.bin_to_text(result, alphabet)

    ECB_wrap._MODULE_CAPABILITIES = {
        'enc': ECB_wrap.encrypt,
        'dec': ECB_wrap.decrypt,
    }

    # Длина вектора инициализации(n/2) - 64/2 = 32 бита
    # (Выборка всех битов вектора - 0xffffffff)
    # ГОСТ Р 34.13-2025 стр.14
    class CTR:
        # На случай нетривиальной процедуры инициализации
        # ГОСТ Р 34.13-2025 стр.12
        @staticmethod
        def _i_transform(iv):
            return (iv & 0xffffffff) << 32

        @staticmethod
        def _ctr_add(ctr):
            return (ctr + 1) & 0xffffffffffffffff

        @classmethod
        def process(cls, key, iv, data, size=None):
            # If no specified size, determine the length of input data
            if size is None:
                size = share.bin_len(data)

            result = []
            t_size = size
            # Transform the initialization vector (iv) using _i_transform method
            ctr = cls._i_transform(iv)
            # Process each block of data (64 bits at a time)
            for block in share.split_blocks(data, 64, t_size):
                # Encrypt the current CTR value using the provided key
                gamma = magma._encrypt_block(key, ctr)

                # Strip gamma CTR value size if block size is less 64 bits
                if t_size < 64:
                    # Вместо lsb должен быть msb, но мы в little-endian
                    gamma = share.lsb(gamma, t_size)

                # XOR the gamma with the data block
                # and append it to the results
                result.append(block ^ gamma)

                t_size -= 64
                ctr = cls._ctr_add(ctr)

            # Concatenate all resulting blocks back together
            return share.concat_blocks(result, 64, size)

        @classmethod
        def encrypt(cls, key, iv, message, size=None):
            return cls.process(key, iv, message, size)

        @classmethod
        def decrypt(cls, key, iv, ciphertext, size=None):
            return cls.process(key, iv, ciphertext, size)


    class CTR_wrap:
        _MODULE_NAME = 'ГОСТ Р 34.12-2015 Режим CTR'
        _MODULE_DEFAULT_ALPHABET_SET = {
            'a': share.alphabet_ru32,
            'to': share.rules_to_ru32,
            'from': share.rules_rv_format
        }
        _MODULE_CAPABILITIES = {}
        _MODULE_KEY_DEFAULT = {}
        _MODULE_KEY_PARAMS = [
            ['key', 'Ключ', int],
            ['iv', 'Вектор инициализации', int]
        ]

        @staticmethod
        def encrypt(cipher_config, message, alphabet):
            message, size = share.text_to_bin(message, alphabet)

            return magma.CTR.encrypt(
                cipher_config['key'],
                cipher_config['iv'],
                message,
                size
            )

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet, size=None):
            result = magma.CTR.decrypt(
                cipher_config['key'],
                cipher_config['iv'],
                ciphertext,
                size
            )

            return share.bin_to_text(result, alphabet)

    CTR_wrap._MODULE_CAPABILITIES = {
        'enc': CTR_wrap.encrypt,
        'dec': CTR_wrap.decrypt,
    }

class kuznyechik:
    _L = [1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148]
    _S = [
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
        119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101,
        90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
        160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
        104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
        183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
        177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
        245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
        222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0,
        98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
        165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
        217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133,
        97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
        116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
    ]

    @classmethod
    def _s_transform(cls, data):
        result = []
        for i in share.split_blocks(data, 8, 128):
            result.append(cls._S[i])

        return share.concat_blocks(result, 8, 128)

    @classmethod
    def _s_transform_r(cls, data):
        result = []
        for i in share.split_blocks(data, 8, 128):
            result.append(cls._S.index(i))

        return share.concat_blocks(result, 8, 128)

    @classmethod
    def _gamma_op(cls, data):
        result = 0
        data = share.split_blocks(data, 8, 128)
        for i in range(len(data)):
            result ^= gf_mult(cls._L[i], data[i], 8, 0x1c3)

        return result

    @classmethod
    def _r_transform(cls, data):
        return cls._gamma_op(data) << 120 | data >> 8

    @classmethod
    def _r_transform_r(cls, data):
        data_t = data & 0xffffffffffffffffffffffffffffff

        return data_t << 8 | cls._gamma_op(data_t << 8 | (data >> 120 & 0xff))

    @classmethod
    def _l_transform(cls, data):
        for _ in range(16):
            data = cls._r_transform(data)

        return data

    @classmethod
    def _l_transform_r(cls, data):
        for _ in range(16):
            data = cls._r_transform_r(data)

        return data

    @classmethod
    def _lsx_transform(cls, k, data):
        data ^= k
        data = cls._s_transform(data)
        data = cls._l_transform(data)

        return data

    @classmethod
    def _slx_transform(cls, k, data):
        data ^= k
        data = cls._l_transform_r(data)
        data = cls._s_transform_r(data)

        return data

    @classmethod
    def _bf_transform(cls, k, a1, a0):
        return cls._lsx_transform(k, a1) ^ a0, a1

    @classmethod
    def _key_shedule(cls, key):
        key = share.split_blocks(key, 128, 256)[::-1]

        con = []
        for i in range(1, 33):
            con.append(cls._l_transform(i))

        round_keys = key
        for i in range(4):
            for j in range(8):
                key = cls._bf_transform(
                    con[i * 8 + j],
                    key[0],
                    key[1]
                )
            round_keys += key

        return round_keys

    @classmethod
    def _all_rounds(cls, round_keys, data):
        for i in range(len(round_keys) - 1):
            data = cls._lsx_transform(round_keys[i], data)

        data ^= round_keys[-1]

        return data

    @classmethod
    def _inv_all_rounds(cls, round_keys, data):
        for i in range(len(round_keys) - 1, 0, -1):
            data = cls._slx_transform(round_keys[i], data)

        data ^= round_keys[0]

        return data

    @classmethod
    def _encrypt_block(cls, key, data):
        return cls._all_rounds(
            cls._key_shedule(key),
            data
        )

    @classmethod
    def _decrypt_block(cls, key, data):
        return cls._inv_all_rounds(
            cls._key_shedule(key),
            data
        )

    class ECB:
        @staticmethod
        def encrypt(key, message, size=-1):
            result = []
            for data in share.split_blocks(message, 128, size):
                result.append(kuznyechik._encrypt_block(key, data))

            return share.concat_blocks(result, 128, size)

        @staticmethod
        def decrypt(key, ciphertext, size=-1):
            result = []
            for data in share.split_blocks(ciphertext, 128, size):
                result.append(kuznyechik._decrypt_block(key, data))

            return share.concat_blocks(result, 128, size)


    class ECB_wrap:
        _MODULE_NAME = 'Кузнечик ECB'
        _MODULE_DEFAULT_ALPHABET_SET = {
            'a': share.alphabet_ru32,
            'to': share.rules_to_ru32,
            'from': share.rules_rv_format
        }
        _MODULE_CAPABILITIES = {}
        _MODULE_KEY_DEFAULT = {}
        _MODULE_KEY_PARAMS = [
            ['key', 'Ключ', int],
        ]
        @staticmethod
        def encrypt(cipher_config, message, alphabet):
            message, _ = share.text_to_bin(message, alphabet)

            return kuznyechik.ECB.encrypt(cipher_config['key'],message)

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet):
            result = kuznyechik.ECB.decrypt(cipher_config['key'], ciphertext)

            return share.bin_to_text(result, alphabet)

    ECB_wrap._MODULE_CAPABILITIES = {
        'enc': ECB_wrap.encrypt,
        'dec': ECB_wrap.decrypt,
    }

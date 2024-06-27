import share
from galois_field import gf_eea, gf_mult

class aes:
    class B128:
        Nk = 4
        Nb = 4
        Nr = 10

    class B192:
        Nk = 6
        Nb = 4
        Nr = 12

    class B256:
        Nk = 8
        Nb = 4
        Nr = 14

    @staticmethod
    def _sub_bytes(data, N):
        result = []
        for block in share.split_blocks(data, 8, N * 8):
            if block > 1:
                block = gf_eea(0x011b, block)

            block ^= share.circular_shift_l(block, 1, 8) \
                ^ share.circular_shift_l(block, 2, 8) \
                ^ share.circular_shift_l(block, 3, 8) \
                ^ share.circular_shift_l(block, 4, 8) \
                ^ 0x63

            result.append(block)

        return share.concat_blocks(result, 8, N * 8)

    @staticmethod
    def _inv_sub_bytes(data, N):
        result = []
        for block in share.split_blocks(data, 8, N * 8):
            block = share.circular_shift_l(block, 1, 8) \
                ^ share.circular_shift_l(block, 3, 8) \
                ^ share.circular_shift_l(block, 6, 8) \
                ^ 0x5

            if block > 0:
                block = gf_eea(0x011b, block)

            result.append(block)

        return share.concat_blocks(result, 8, N * 8)

    @staticmethod
    def _shift_rows(data):
        result = [0] * 4
        data = share.split_blocks(data, 32)
        for i in range(4):
            for j in range(4):
                result[(j + i) % 4] |= data[j] & (0xff << (3 - i) * 8)

        return share.concat_blocks(result, 32, 128)

    @staticmethod
    def _inv_shift_rows(data):
        result = [0] * 4
        data = share.split_blocks(data, 32)
        for i in range(4):
            for j in range(4):
                result[(j - i) % 4] |= data[j] & (0xff << (3 - i) * 8)

        return share.concat_blocks(result, 32, 128)

    @staticmethod
    def _mix_columns(data):
        result = [0] * 4
        data = share.split_blocks(data, 32)
        for i in range(4):
            s = [
                data[i] & 0xff,
                (data[i] >> 8) & 0xff,
                (data[i] >> 16) & 0xff,
                (data[i] >> 24) & 0xff,
            ]

            for j in range(4):
                result[i] |= (
                    gf_mult(0x02, s[(j + 0) % 4], 8, 0x011b)
                    ^ s[(j + 1) % 4]
                    ^ s[(j + 2) % 4]
                    ^ gf_mult(0x03, s[(j + 3) % 4], 8, 0x011b)
                ) << (8 * j)

        return share.concat_blocks(result, 32, 128)

    @staticmethod
    def _inv_mix_columns(data):
        result = [0] * 4
        data = share.split_blocks(data, 32)
        for i in range(4):
            s = [
                data[i] & 0xff,
                (data[i] >> 8) & 0xff,
                (data[i] >> 16) & 0xff,
                (data[i] >> 24) & 0xff,
            ]

            for j in range(4):
                result[i] |= (
                    gf_mult(0x0e, s[(j + 0) % 4], 8, 0x011b)
                    ^ gf_mult(0x09, s[(j + 1) % 4], 8, 0x011b)
                    ^ gf_mult(0x0d, s[(j + 2) % 4], 8, 0x011b)
                    ^ gf_mult(0x0b, s[(j + 3) % 4], 8, 0x011b)
                ) << (8 * j)

        return share.concat_blocks(result, 32)

    @staticmethod
    def _rot_word(data):
        return share.circular_shift_l(data, 8, 32)

    @classmethod
    def _sub_word(cls, data):
        return cls._sub_bytes(data, 4)

    @staticmethod
    def _calc_rcon():
        result = [1]
        for _ in range(1, 10):
            result.append(
                gf_mult(0x02, result[-1], 8, 0x011b)
            )

        return result

    @staticmethod
    def _add_round_key(key, data):
        return data ^ share.concat_blocks(key[::-1], 32)

    @classmethod
    def _key_shedule(cls, key, m):
        w = share.split_blocks(key, 32, 32 * m.Nk)[::-1]
        rcon = cls._calc_rcon()
        for i in range(m.Nk, m.Nb * (m.Nr + 1)):
            word = w[-1]
            if i % m.Nk == 0:
                word = cls._rot_word(
                    cls._sub_word(word)
                ) ^ (rcon[(i // m.Nk) - 1] << 24)
            elif m.Nk > 6 and i % m.Nk == 4:
                word = cls._sub_word(word)

            w.append(w[i - m.Nk] ^ word)

        return w

    @classmethod
    def _round(cls, round_keys, data, N):
        data = cls._sub_bytes(data, N)
        data = cls._shift_rows(data)
        data = cls._mix_columns(data)
        data = cls._add_round_key(round_keys, data)

        return data

    @classmethod
    def _inv_round(cls, round_keys, data, N):
        data = cls._inv_shift_rows(data)
        data = cls._inv_sub_bytes(data, N)
        data = cls._add_round_key(round_keys, data)
        data = cls._inv_mix_columns(data)

        return data

    @classmethod
    def _all_rounds(cls, keys, data, m):
        N = m.Nb * 4

        data = cls._add_round_key(keys[0:m.Nb], data)
        for i in range(1, m.Nr):
            data = cls._round(keys[i * m.Nb:(i + 1) * m.Nb], data, N)

        data = cls._sub_bytes(data, N)
        data = cls._shift_rows(data)
        data = cls._add_round_key(keys[m.Nr * m.Nb:(m.Nr + 1) * m.Nb], data)

        return data

    @classmethod
    def _inv_all_rounds(cls, keys, data, m):
        N = m.Nb * 4

        data = cls._add_round_key(keys[m.Nr * m.Nb:(m.Nr + 1) * m.Nb], data)
        for i in range(m.Nr - 1, 0, -1):
            data = cls._inv_round(keys[i * m.Nb:(i + 1) * m.Nb], data, N)

        data = cls._inv_shift_rows(data)
        data = cls._inv_sub_bytes(data, N)
        data = cls._add_round_key(keys[0:m.Nb], data)

        return data

    @classmethod
    def _encrypt_block(cls, key, data, m):
        return cls._all_rounds(
            cls._key_shedule(key, m),
            data,
            m
        )

    @classmethod
    def _decrypt_block(cls, key, data, m):
        return cls._inv_all_rounds(
            cls._key_shedule(key, m),
            data,
            m
        )

    @classmethod
    def _id_to_m(cls, m):
        m_lut = {0: cls.B128, 1: cls.B192, 2: cls.B256}
        if m in m_lut:
            m = m_lut[m]
        else:
            m = m_lut[0]

        return m

    class ECB:
        @staticmethod
        def encrypt(key, message, m, size=-1):
            m = aes._id_to_m(m)
            result = []
            for data in share.split_blocks(message, 128, size):
                result.append(aes._encrypt_block(key, data, m))

            return share.concat_blocks(result, 128, size)

        @staticmethod
        def decrypt(key, ciphertext, m, size=-1):
            m = aes._id_to_m(m)
            result = []
            for data in share.split_blocks(ciphertext, 128, size):
                result.append(aes._decrypt_block(key, data, m))

            return share.concat_blocks(result, 128, size)


    class ECB_wrap:
        _MODULE_NAME = 'AES ECB'
        _MODULE_DEFAULT_ALPHABET_SET = {
            'a': share.alphabet_ru32,
            'to': share.rules_to_ru32,
            'from': share.rules_rv_format
        }
        _MODULE_CAPABILITIES = {}
        _MODULE_KEY_DEFAULT = {}
        _MODULE_KEY_PARAMS = [
            ['m', 'Размер ключа', int],
            ['key', 'Ключ', int],
        ]
        @staticmethod
        def encrypt(cipher_config, message, alphabet):
            message, _ = share.text_to_bin(message, alphabet)

            return aes.ECB.encrypt(
                cipher_config['key'],
                message,
                cipher_config['m']
            )

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet):
            result = aes.ECB.decrypt(
                cipher_config['key'],
                ciphertext,
                cipher_config['m']
            )

            return share.bin_to_text(result, alphabet)

    ECB_wrap._MODULE_CAPABILITIES = {
        'enc': ECB_wrap.encrypt,
        'dec': ECB_wrap.decrypt,
    }

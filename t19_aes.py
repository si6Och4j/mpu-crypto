import share
from galois_field import gf_eea, gf_mult

class rijndeal:
    class AES128:
        Nk = 4
        Nb = 4
        Nr = 10
        C = [0, 1, 2, 3]

    class AES192:
        Nk = 6
        Nb = 4
        Nr = 12
        C = [0, 1, 2, 3]

    class AES256:
        Nk = 8
        Nb = 4
        Nr = 14
        C = [0, 1, 2, 3]

    class RJD256:
        Nk = 8
        Nb = 8
        Nr = 14
        C = [0, 1, 3, 4]

    _SBox = []
    _InvSBox = []

    @classmethod
    def _getSBoxValue(cls, value):
        if len(cls._SBox) > 0:
            return cls._SBox[value]

        for i in range(0x100):
            block = gf_eea(0x011b, i)
            block ^= share.circular_shift_l(block, 1, 8) \
                ^ share.circular_shift_l(block, 2, 8) \
                ^ share.circular_shift_l(block, 3, 8) \
                ^ share.circular_shift_l(block, 4, 8) \
                ^ 0x63
            cls._SBox.append(block)

        return cls._SBox[value]

    @classmethod
    def _getInvSBoxValue(cls, value):
        if len(cls._InvSBox) > 0:
            return cls._InvSBox[value]

        for block in range(0x100):
            block = share.circular_shift_l(block, 1, 8) \
                ^ share.circular_shift_l(block, 3, 8) \
                ^ share.circular_shift_l(block, 6, 8) \
                ^ 0x5
            block = gf_eea(0x011b, block)

            cls._InvSBox.append(block)

        return cls._InvSBox[value]

    @staticmethod
    def _unpack_column(data):
        return [
            data & 0xff,
            (data >> 8) & 0xff,
            (data >> 16) & 0xff,
            (data >> 24) & 0xff,
        ]

    @staticmethod
    def _pack_column(data):
        return (
            data[0]
            | (data[1] << 8)
            | (data[2] << 16)
            | (data[3] << 24)
        ) & 0xffffffff

    @classmethod
    def _proc_bytes(cls, data, n, call):
        for i in range(n):
            result = []
            for block in cls._unpack_column(data[i]):
                result.append(call(block))

            data[i] = cls._pack_column(result)

        return data

    @classmethod
    def _sub_bytes(cls, data, n):
        return cls._proc_bytes(data, n, cls._getSBoxValue)

    @classmethod
    def _inv_sub_bytes(cls, data, n):
        return cls._proc_bytes(data, n, cls._getInvSBoxValue)

    @staticmethod
    def _proc_shift_rows(data, m, call):
        result = [0] * m.Nb
        for j in range(m.Nb):
            for i in range(4):
                result[j] |= data[call(j, m.C[i]) % m.Nb] & (0xff << ((3 - i) * 8))

        for i in range(m.Nb):
            data[i] = result[i]

        return data

    @classmethod
    def _shift_rows(cls, data, m):
        return cls._proc_shift_rows(data, m, lambda a, b: a - b)

    @classmethod
    def _inv_shift_rows(cls, data, m):
        return cls._proc_shift_rows(data, m, lambda a, b: a + b)

    @classmethod
    def _mix_columns(cls, data, m):
        for i in range(m.Nb):
            result = 0
            s = cls._unpack_column(data[i])
            for j in range(4):
                result |= (
                    gf_mult(0x02, s[j], 8, 0x011b) # (j + 0) % 4
                    ^ s[(j + 1) % 4]
                    ^ s[(j + 2) % 4]
                    ^ gf_mult(0x03, s[(j + 3) % 4], 8, 0x011b)
                ) << (8 * j)

            data[i] = result

        return data

    @classmethod
    def _inv_mix_columns(cls, data, m):
        for i in range(m.Nb):
            result = 0
            s = cls._unpack_column(data[i])
            for j in range(4):
                result |= (
                    gf_mult(0x0e, s[j], 8, 0x011b) # (j + 0) % 4
                    ^ gf_mult(0x09, s[(j + 1) % 4], 8, 0x011b)
                    ^ gf_mult(0x0d, s[(j + 2) % 4], 8, 0x011b)
                    ^ gf_mult(0x0b, s[(j + 3) % 4], 8, 0x011b)
                ) << (8 * j)

            data[i] = result

        return data

    @staticmethod
    def _add_round_key(data, key, m):
        for i in range(m.Nb):
            data[i] ^= key[m.Nb - i - 1]

        return data

    @classmethod
    def _round(cls, data, key, m):
        cls._sub_bytes(data, m.Nb)
        cls._shift_rows(data, m)
        cls._mix_columns(data, m)
        cls._add_round_key(data, key, m)

        return data

    @classmethod
    def _inv_round(cls, data, key, m):
        cls._inv_shift_rows(data, m)
        cls._inv_sub_bytes(data, m.Nb)
        cls._add_round_key(data, key, m)
        cls._inv_mix_columns(data, m)

        return data

    @classmethod
    def _all_rounds(cls, data, keys, m):
        cls._add_round_key(data, keys[0:m.Nb], m)
        for i in range(1, m.Nr):
            base = i * m.Nb
            cls._round(data, keys[base:base + m.Nb], m)

        cls._sub_bytes(data, m.Nb)
        cls._shift_rows(data, m)

        base = m.Nr * m.Nb
        cls._add_round_key(data, keys[base:base + m.Nb], m)

        return data

    @classmethod
    def _inv_all_rounds(cls, data, keys, m):
        base = m.Nr * m.Nb
        cls._add_round_key(data, keys[base:base + m.Nb], m)
        for i in range(m.Nr - 1, 0, -1):
            base = i * m.Nb
            data = cls._inv_round(data, keys[base:base + m.Nb], m)

        data = cls._inv_shift_rows(data, m)
        data = cls._inv_sub_bytes(data, m.Nb)
        data = cls._add_round_key(data, keys[0:m.Nb], m)

        return data

    @staticmethod
    def _rot_word(data):
        return share.circular_shift_l(data, 8, 32)

    @classmethod
    def _sub_word(cls, data):
        return cls._sub_bytes([data], 1)[0]

    @staticmethod
    def _calc_rcon():
        result = [1]
        for i in range(20): # 1, 10
            result.append(
                gf_mult(0x02, result[i], 8, 0x011b)
            )

        return result

    @classmethod
    def _key_shedule(cls, key, m):
        rcon = cls._calc_rcon()
        word = key[m.Nk - 1]
        for i in range(m.Nk, m.Nb * (m.Nr + 1)):
            if i % m.Nk == 0:
                word = cls._rot_word(
                    cls._sub_word(word)
                ) ^ (rcon[(i // m.Nk) - 1] << 24)
            elif m.Nk > 6 and i % m.Nk == 4:
                word = cls._sub_word(word)

            word ^= key[i - m.Nk]
            key.append(word)

        return key

    @classmethod
    def _mn_to_m(cls, m):
        m_lut = {
            0: cls.AES128,
            1: cls.AES192,
            2: cls.AES256,
            3: cls.RJD256,
        }
        if not m in m_lut:
            raise Exception('Unknown encryption mode')

        return m_lut[m]

    class ECB:
        @staticmethod
        def encrypt(key, message, mn, size=-1):
            m = rijndeal._mn_to_m(mn)

            result = []
            round_keys = rijndeal._key_shedule(
                share.split_blocks(key, 32, m.Nk * 32)[::-1],
                m
            )

            b_size = m.Nb * 32
            for data in share.split_blocks(message, b_size, size):
                result += rijndeal._all_rounds(
                    share.split_blocks(data, 32, b_size),
                    round_keys,
                    m
                )

            return share.concat_blocks(result)

        @staticmethod
        def decrypt(key, ciphertext, mn, size=-1):
            m = rijndeal._mn_to_m(mn)

            result = []
            round_keys = rijndeal._key_shedule(
                share.split_blocks(key, 32, m.Nk * 32)[::-1],
                m
            )

            b_size = m.Nb * 32
            for data in share.split_blocks(ciphertext, b_size, size):
                a = [hex(v) for v in share.split_blocks(data)]
                b = [hex(v) for v in round_keys]
                result += rijndeal._inv_all_rounds(
                    share.split_blocks(data, 32, b_size),
                    round_keys,
                    m
                )

            return share.concat_blocks(result)


    class ECB_wrap:
        _MODULE_NAME = 'Rijndeal'
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

            return rijndeal.ECB.encrypt(
                cipher_config['key'],
                message,
                cipher_config['m']
            )

        @staticmethod
        def decrypt(cipher_config, ciphertext, alphabet):
            result = rijndeal.ECB.decrypt(
                cipher_config['key'],
                ciphertext,
                cipher_config['m']
            )

            return share.bin_to_text(result, alphabet)

    ECB_wrap._MODULE_CAPABILITIES = {
        'enc': ECB_wrap.encrypt,
        'dec': ECB_wrap.decrypt,
    }

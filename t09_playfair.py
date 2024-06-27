import share

class playfair:
    _MODULE_NAME = 'Шифр Плэйфера'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru30,
        'to': share.rules_to_ru30,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['key', 'Лозунг', str]
    ]

    @staticmethod
    def _create_field(key, alphabet, size = 6):
        assert len(alphabet) % size == 0

        result = {
            'reverse_index': {},
            'field': []
        }
        row_cnt = 0
        col_cnt = 0
        data = []
        for lst in [key, alphabet]:
            for v in lst:
                if v in result['reverse_index']:
                    continue

                if col_cnt == size:
                    result['field'].append(data)
                    data = []
                    col_cnt = 0
                    row_cnt += 1

                data.append(v)
                result['reverse_index'][v] = [row_cnt, col_cnt]
                col_cnt += 1

        if len(data) > 0:
            result['field'].append(data)

        return result

    @classmethod
    def encrypt(cls, cipher_config, message, alphabet):
        col_cnt = cipher_config['per_row'] if 'per_row' in cipher_config else 6
        key = cls._create_field(cipher_config['key'], alphabet, col_cnt)

        pairs = []
        msg_raw = list(message)
        msg_len = len(message)
        # Padding message
        while msg_len > 0:
            c1 = msg_raw.pop(0)
            msg_len -= 1

            #if not (msg_len != 0 and c1 != msg_raw[0]):
            if msg_len == 0:
                c2 = 'я'
            else:
                c2 = msg_raw.pop(0)
                msg_len -= 1

            pairs.append([c1, c2])

        ciphertext = []
        row_cnt = len(key['field'])
        for c1, c2 in pairs:
            c1 = key['reverse_index'][c1].copy()
            c2 = key['reverse_index'][c2].copy()

            # Check if the column index of
            # the first and second characters are the same
            if c1[1] == c2[1]:
                # If true, increase the row index
                # of the first and second characters by 1 (modulo row count)
                c1[0] = (c1[0] + 1) % row_cnt
                c2[0] = (c2[0] + 1) % row_cnt
            # Check if the row index of the
            # first and second characters are the same
            elif c1[0] == c2[0]:
                # If true, increase the column index of
                # the first and second characters by 1 (modulo column count)
                c1[1] = (c1[1] + 1) % col_cnt
                c2[1] = (c2[1] + 1) % col_cnt
            else:
                # If neither, swap the column
                # indexes of the first and second characters
                c1[1], c2[1] = c2[1], c1[1]

            ciphertext.append(key['field'][c1[0]][c1[1]])
            ciphertext.append(key['field'][c2[0]][c2[1]])

        return ''.join(ciphertext)

    @classmethod
    def decrypt(cls, cipher_config, ciphertext, alphabet):
        # Checks if length of ciphertext is even
        assert len(ciphertext) % 2 == 0

        col_cnt = cipher_config['per_row'] if 'per_row' in cipher_config else 6
        key = cls._create_field(cipher_config['key'], alphabet, col_cnt)

        message = []
        row_cnt = len(key['field'])

        # Decrypts each pair of characters in ciphertext
        for i in range(0, len(ciphertext), 2):
            c1, c2 = ciphertext[i:i+2]

            # Copies the reverse index values from key for current characters
            c1 = key['reverse_index'][c1].copy()
            c2 = key['reverse_index'][c2].copy()

            # Swaps row or column indices based on corresponding
            # character indices having the same or different columns
            if c1[1] == c2[1]:
                c1[0] = (c1[0] - 1) % row_cnt
                c2[0] = (c2[0] - 1) % row_cnt
            elif c1[0] == c2[0]:
                c1[1] = (c1[1] - 1) % col_cnt
                c2[1] = (c2[1] - 1) % col_cnt
            else:
                c2[1], c1[1] = c1[1], c2[1]

            message.append(key['field'][c1[0]][c1[1]])
            message.append(key['field'][c2[0]][c2[1]])

        return ''.join(message)

playfair._MODULE_CAPABILITIES = {
    'enc': playfair.encrypt,
    'dec': playfair.decrypt,
}

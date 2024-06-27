import share

class vertical_shuffle:
    _MODULE_NAME = 'Вертикальная перестановка'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['key', 'Слово-ключ', str]
    ]

    @staticmethod
    def _key_to_order(key):
        char_lut = sorted(list(key))

        return [char_lut.index(v) for v in key]

    @classmethod
    def encrypt(cls, cipher_config, message, alphabet):
        # Generate key based on given configuration and alphabet
        key = cls._key_to_order(cipher_config['key'])
        key_len = len(key)
        assert len(set(key)) == key_len

        matrix = []
        # Determine the number of columns in the matrix
        col_cnt = len(message) // key_len
        # Calculate the overflow, i.e.,
        # the remaining length of message after filling the complete matrices
        overflow = len(message) % key_len
        for i in range(key_len):
            matrix.append([
                message[key_len * j + i]
                for j in range(col_cnt + int(i < overflow))
            ])

        # Initialize an empty string to store the encrypted text
        ciphertext = ''

        # Iterate through each character in the key and
        # add corresponding columns' characters to form the ciphertext
        for i in key:
            ciphertext += ''.join(matrix[i])

        return ciphertext

    @classmethod
    def decrypt(cls, cipher_config, ciphertext, alphabet):
        # Calculate the order of the key based on the given key and alphabet.
        key = cls._key_to_order(cipher_config['key'])

        key_len = len(key)
        assert len(set(key)) == key_len

        # Calculate the number of rows in the matrix
        # based on the length of the ciphertext and the key.
        row_cnt = len(ciphertext) // key_len
        # Determine if there is an overflow.
        overflow = len(ciphertext) % key_len
        # Initialize an empty dictionary to store each column of the matrix.
        cnt = 0
        offset = 0
        matrix = {}

        # Loop through each character in the key
        # and calculate its position in the matrix.
        for i in key:
            # Determine if the current character is within the overflow.
            in_overflow = i < overflow

            # Calculate the base index of the current column in the matrix.
            base = row_cnt * cnt + offset
            # Assign the corresponding substring from
            # the ciphertext to the current key.
            matrix[i] = ciphertext[base:base + row_cnt + int(in_overflow)]
            cnt += 1
            offset += int(in_overflow)

        message = ''

        # Loop through each row and column of the matrix
        # to build the decrypted message.
        for i in range(row_cnt):
            for j in range(key_len):
                message += matrix[j][i]

        # If there is an overflow, add thelast characters
        # from each overflowed column to the message.
        for j in range(overflow):
            message += matrix[j][-1]

        return message

vertical_shuffle._MODULE_CAPABILITIES = {
    'enc': vertical_shuffle.encrypt,
    'dec': vertical_shuffle.decrypt,
}

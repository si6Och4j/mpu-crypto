import share

class matrix:
    _MODULE_NAME = 'Матричный шифр'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['key_size', 'Размер матрицы', int],
        ['key', 'Ключ', str]
    ]

    @staticmethod
    def _invert(AM, IM):
        for fd in range(len(AM)):
            fdScaler = 1.0 / AM[fd][fd]
            for j in range(len(AM)):
                AM[fd][j] *= fdScaler
                IM[fd][j] *= fdScaler

            for i in list(range(len(AM)))[0:fd] + list(range(len(AM)))[fd+1:]:
                crScaler = AM[i][fd]
                for j in range(len(AM)):
                    AM[i][j] = AM[i][j] - crScaler * AM[fd][j]
                    IM[i][j] = IM[i][j] - crScaler * IM[fd][j]

        return IM


    @staticmethod
    def _create_one(size):
        result = []
        cnt = 0
        for _ in range(size):
            # Append a new sublist to result
            # Sublist is created with initial 0s based on current count 'cnt',
            # then a 1 and finally 0s up to the size - 1 but not including size
            result.append(
                [0 for _ in range(cnt)]
                    + [1]
                    + [0 for _ in range(cnt, size - 1)]
            )
            cnt += 1

        return result

    @staticmethod
    def _to_mat(data, size):
        return [
            [
                data[j]
                for j in range(i, i + size)
            ]
            for i in range(0, len(data), size)
        ]

    # Static method for multiplying a matrix with a vector
    @staticmethod
    def _mul_mat_on_vec(M, V):
    # Initialize an empty list to store the results
        result = []

        # Iterate through each row in the matrix M
        for row in M:
            # Initialize variables for total and vector counter
            total = 0
            vec_cnt = 0

            # Perform element-wise multiplication and addition of
            # the matrix elements with the corresponding vector elements,
            # then sum them up
            for val in row:
                total += val * V[vec_cnt]
                vec_cnt += 1

            # Round off the result to the nearest integer and append it to the list
            result.append(round(total))

        # Return the final list of results
        return result

    @classmethod
    def encrypt(cls, cipher_config, message, alphabet):
        key_n = cipher_config['key_size']
        key = cls._to_mat(
            [int(v) for v in cipher_config['key'].split(' ')],
            key_n
        )

        # Convert message to numerical representation using given alphabet
        msg_raw = share.text_to_nums(message, alphabet)

        # Pad message with zeros if its length is not multiple of key size
        padding_size = len(msg_raw) % key_n
        if padding_size > 0:
            msg_raw += [0 for _ in range(key_n - padding_size)]

        # Encrypt message by multiplying key matrix with each chunk of message
        ciphertext = []
        for i in range(0, len(msg_raw), key_n):
            ciphertext += cls._mul_mat_on_vec(key, msg_raw[i:i + key_n])

        # Return final encrypted message as space-separated string of numbers
        return ' '.join([str(v) for v in ciphertext])

    @classmethod
    def decrypt(cls, cipher_config, ciphertext, alphabet):
    # Extracts key size from configuration.
        key_n = cipher_config['key_size']

        # Generates inverted key matrix.
        key = cls._invert(
            # Converts key string into list of integers and creates key matrix.
            cls._to_mat(
                [int(v) for v in cipher_config['key'].split(' ')],
                key_n
            ),
            # Creates identity matrix of the same size as key matrix.
            cls._create_one(key_n)
        )

        # Converts ciphertext to list of integers.
        message = []
        ciphertext = [int(v) for v in ciphertext.split(' ')]

        # Decrypts each segment of ciphertext using matrix multiplication.
        for i in range(0, len(ciphertext), key_n):
            message += cls._mul_mat_on_vec(key, ciphertext[i:i + key_n])

        # Converts decrypted integers to their
        # corresponding characters using alphabet.
        return ''.join(share.nums_to_text(message, alphabet))

matrix._MODULE_CAPABILITIES = {
    'enc': matrix.encrypt,
    'dec': matrix.decrypt,
}

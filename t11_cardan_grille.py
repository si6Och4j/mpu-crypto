import secrets
import share

class cardan_grille:
    _MODULE_NAME = 'Решетка Кардано'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['row_n', 'Колл-во строк', int],
        ['row_size', 'Колл-во столбцов в строке', int],
        ['key', 'Состояние решётки', int]
    ]
    _MODULE_KEYGEN_PARAMS = [
        ['row_n', 'Колл-во строк', int],
        ['row_size', 'Колл-во столбцов в строке', int],
    ]

    @staticmethod
    def keygen(keygen_config):
        row_n = int (keygen_config['row_n'])
        row_size = int (keygen_config['row_size'])

        assert row_n % 2 == 0
        assert row_size % 2 == 0

        rows = [0] * row_n
        for y in range(row_n // 2):
            for x in range(row_size // 2):
                q = secrets.randbelow(4)
                y = [y, row_n - y - 1][q % 2]
                x = [x, row_size - x - 1][q >= 2]

                rows[y] |= 1 << x

        for i in rows:
            print(bin(i))

        return share.concat_blocks(rows, row_size)

    @staticmethod
    def _form_key(cipher_config):
        row_n = int (cipher_config['row_n'])
        row_size = int (cipher_config['row_size'])
        size = row_n * row_size

        assert row_n % 2 == 0
        assert row_size % 2 == 0

        key = int(cipher_config['key'])
        r_key = share.byte_swap(key, size, 1)

        key_blocks = share.split_blocks(key, row_size, size)
        r_key_blocks = share.split_blocks(r_key, row_size, size)

        return [key_blocks, r_key_blocks, r_key_blocks[::-1], key_blocks[::-1]]

    @classmethod
    def encrypt(cls, cipher_config, message, alphabet):
        # Define variables from cipher configuration
        row_n = int(cipher_config['row_n'])
        row_size = int(cipher_config['row_size'])

        message = list(message)
        ciphertext = [None] * (row_n * row_size)

        # Form key for encryption using _form_key class method
        for block in cls._form_key(cipher_config):
            row_cnt = 0
            for mask in block:
                # Calculate base index for current character position
                # based on row and column
                base = (row_cnt % row_n) * row_size
                for i in range(row_size):
                    i += base

                    # If current mask bit is set and message is not empty
                    if mask & 1 and message:
                        # Replace None value at position 'i' with
                        # first character from message
                        ciphertext[i] = message.pop(0)
                    # If current position in ciphertext is None,
                    # replace it with random character from alphabet
                    elif ciphertext[i] is None:
                        ciphertext[i] = secrets.choice(alphabet)

                    mask >>= 1

                row_cnt += 1

        return ''.join(ciphertext)

    @classmethod
    def decrypt(cls, cipher_config, ciphertext, alphabet):
        row_n = int(cipher_config['row_n'])
        row_size = int(cipher_config['row_size'])
        # size = row_n * row_size

        message = ''

        # Forms keys from the configuration.
        for block in cls._form_key(cipher_config):
            # Initializes a counter for keeping track of the current row.
            row_cnt = 0

            # Decrypts each character based on the mask
            # and current position in the ciphertext.
            for mask in block:
                base = (row_cnt % row_n) * row_size
                for i in range(row_size):
                    i += base

                    # If the bit at the current mask position is set,
                    # appends the corresponding character
                    # from ciphertext to message.
                    if mask & 1:
                        message += ciphertext[i]

                    mask >>= 1

                row_cnt += 1

        return message

cardan_grille._MODULE_CAPABILITIES = {
    'enc': cardan_grille.encrypt,
    'dec': cardan_grille.decrypt,
}

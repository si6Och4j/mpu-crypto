import share

class polybius_square:
    _MODULE_NAME = 'Квадрат Полибия'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['row', 'Колл-во символов в строке', int]
    ]

    @staticmethod
    def encrypt(cipher_config, message, alphabet):
        # Get the number of characters per row from cipher configuration
        row = cipher_config['row']

        # Initialize an empty list to store encrypted numbers
        ciphertext = []

        # Convert each character in message to its
        # corresponding number using text_to_nums function
        for char in share.text_to_nums(message, alphabet, 0):
            # Calculate the row number and column number
            # based on row value
            n1 = char // row
            n2 = char - n1 * row

            # Append the numbers as string in ciphertext list
            ciphertext.append(str(n1 + 1) + str(n2 + 1))

        return ''.join(ciphertext)

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        row = cipher_config['row']

        message = []
        # Loop through ciphertext with step 2
        for i in range(0, len(ciphertext), 2):
            n1, n2 = ciphertext[i:i+2]

            # Append decrypted value to message list
            message.append((int(n1) - 1) * row + int(n2))

        return ''.join(share.nums_to_text(message, alphabet))

polybius_square._MODULE_CAPABILITIES = {
    'enc': polybius_square.encrypt,
    'dec': polybius_square.decrypt,
}

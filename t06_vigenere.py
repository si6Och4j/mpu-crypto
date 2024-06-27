import share

class vigenere:
    _MODULE_NAME = 'Шифр Виженера'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['p', 'Буква-ключ', str]
    ]

    @staticmethod
    def encrypt(cipher_config, message, alphabet):
        # Convert the ciphertext to a list of character indices
        # and add the key's indices
        p = share.text_to_nums(cipher_config['p'] + message, alphabet)
        n = len(alphabet)

        i = 0
        ciphertext = []
        for char in share.text_to_nums(message, alphabet):
            # Calculate the encryption of each character
            # by adding the key's indices
            ciphertext.append((char + p[i] - 1) % n)
            i += 1

        return ''.join(share.nums_to_text(ciphertext, alphabet))

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        n = len(alphabet)

        message = []
        p = alphabet.index(cipher_config['p']) + 1
        for char in share.text_to_nums(ciphertext, alphabet):
            # Calculate the each original character
            # by subtracting the key's indices
            p = (char - p + 1) % n
            message.append(p)

        return ''.join(share.nums_to_text(message, alphabet))

vigenere._MODULE_CAPABILITIES = {
    'enc': vigenere.encrypt,
    'dec': vigenere.decrypt,
}

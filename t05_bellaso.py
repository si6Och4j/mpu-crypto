import share

class bellaso:
    _MODULE_NAME = 'Шифр Белазо'
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
    def encrypt(cipher_config, message, alphabet):
        # Extract key from cipher_config using text_to_nums utility function
        key = share.text_to_nums(cipher_config['key'], alphabet)
        key_n = len(key)
        n = len(alphabet)

        i = 0
        ciphertext = []
        for char in share.text_to_nums(message, alphabet):
            # Encrypt current letter by adding key[i] and subtracting 1
            # then taking the modulo with alphabet length
            ciphertext.append((char + key[i] - 1) % n)
            i = (i + 1) % key_n

        return ''.join(share.nums_to_text(ciphertext, alphabet))

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        key = share.text_to_nums(cipher_config['key'], alphabet)
        key_n = len(key)
        n = len(alphabet)

        i = 0
        message = []
        for char in share.text_to_nums(ciphertext, alphabet):
            # Calculate the decrypted character
            # by subtracting the corresponding key
            # value and wrapping around if necessary
            message.append((char - key[i] + 1) % n)
            # Increment the index i in a circular manner
            i = (i + 1) % key_n

        return ''.join(share.nums_to_text(message, alphabet))

bellaso._MODULE_CAPABILITIES = {
    'enc': bellaso.encrypt,
    'dec': bellaso.decrypt,
}

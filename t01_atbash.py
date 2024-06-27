import share

class atbash:
    _MODULE_NAME = 'Шифр Атбаш'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = []

    @staticmethod
    def process(cipher_config, message, alphabet):
        # Get the length of the alphabet
        n = len(alphabet)

        # Initialize an empty list to store encrypted characters
        ciphertext = []

        # Convert each character in the message to its
        #  corresponding number using the provided alphabet and zero offset
        for char in share.text_to_nums(message, alphabet, 0):
            # Append the difference between the length
            # of the alphabet and the character's number to the ciphertext list
            ciphertext.append(n - char)

        # Convert the encrypted numbers back
        # to their corresponding characters using the provided alphabet
        return ''.join(share.nums_to_text(ciphertext, alphabet))


atbash._MODULE_CAPABILITIES = {
    'enc': atbash.process,
    'dec': atbash.process,
}

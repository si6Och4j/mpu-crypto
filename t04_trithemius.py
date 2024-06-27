import share

class trithemius:
    _MODULE_NAME = 'Шифр Тритемия'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = []

    @staticmethod
    def encrypt(cipher_config, message, alphabet):
        n = len(alphabet)

        i = 0
        ciphertext = []
        for char in share.text_to_nums(message, alphabet):
            # Append the encrypted number (m + i) % n to the list
            ciphertext.append((char + i) % n)
            i += 1

        return ''.join(share.nums_to_text(ciphertext, alphabet))

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        n = len(alphabet)

        i = 0
        message = []
        # Convert each character in encrypted_message
        # to its corresponding number using the alphabet
        for char in share.text_to_nums(ciphertext, alphabet):
            # Append the decrypted number (e - i) % n to the list
            message.append((char - i) % n)
            i += 1

        return ''.join(share.nums_to_text(message, alphabet))

trithemius._MODULE_CAPABILITIES = {
	'enc': trithemius.encrypt,
	'dec': trithemius.decrypt,
}

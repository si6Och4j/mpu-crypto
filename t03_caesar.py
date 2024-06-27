import share

class caesar:
    _MODULE_NAME = 'Шифр Цезаря'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['i', 'Сдвиг алфавита', int]
    ]

    @staticmethod
    def encrypt(cipher_config, message, alphabet):
        # Assign the value of 'i' from cipher_config to variable i
        i = cipher_config['i']

        # Get the length of the alphabet
        n = len(alphabet)

        # Create an empty list named ciphertext to store encrypted numbers
        ciphertext = []

        # Convert each character in message to its corresponding number
        # using share.text_to_nums and
        # then encrypt it by adding 'i' and applying modulo operation with
        # length of alphabet
        for char in share.text_to_nums(message, alphabet):
            ciphertext.append((char + i) % n)

        return ''.join(share.nums_to_text(ciphertext, alphabet))

    @staticmethod
    def decrypt(cipher_config, ciphertext, alphabet):
        i = cipher_config['i']
        n = len(alphabet)

        # Iterate through each character in the given ciphertext
        # using text_to_nums function and append the decrypted number
        # to the message list
        message = []
        for char in share.text_to_nums(ciphertext, alphabet):
            # Subtract 'i' from the number and take the modulo
            # with the length of the alphabet
            message.append((char - i) % n)

        # Join all decrypted numbers in the list to form the decrypted message using nums_to_text function
        return ''.join(share.nums_to_text(message, alphabet))

caesar._MODULE_CAPABILITIES = {
    'enc': caesar.encrypt,
    'dec': caesar.decrypt,
}

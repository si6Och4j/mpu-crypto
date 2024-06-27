from lfsr import lfsr_ng, calc_major
import share

class a5_1:
    _MODULE_NAME = 'Шифр А5/1'
    _MODULE_DEFAULT_ALPHABET_SET = {
        'a': share.alphabet_ru32,
        'to': share.rules_to_ru32,
        'from': share.rules_rv_format
    }
    _MODULE_CAPABILITIES = {}
    _MODULE_KEY_DEFAULT = {}
    _MODULE_KEY_PARAMS = [
        ['key', 'Исходное состояние регистров', int],
    ]

    _LFSR_CONFIG = [
        {
            # Length of the LFSR generator
            'length': 19,
            # Tapped bits used in the feedback polynomial
            'tapped_bits': [13, 16, 17, 18],
            # Majority bit positions for feedback
            'major_bits': [],
            # Synchronization bit position
            'sync_bit': 8,
        },
        {
            'length': 22,
            'tapped_bits': [20, 21],
            'major_bits': [],
            'sync_bit': 10,
        },
        {
            'length': 23,
            'tapped_bits': [7, 20, 21, 22],
            'major_bits': [],
            'sync_bit': 10,
        }
    ]

    @classmethod
    def _lfsr_set_frame_num(cls, state, n):
        """Set frame number for all the LFSR generators in a state list"""

        for s in state:
            s.update_frame_num(n)

        for _ in range(100):
            cls._lfsr_get_bit(state)

    @classmethod
    def _lfsr_create(cls, key, frame_n=0):
        """Create LFSR generators with given key and initial frame number"""

        result = []
        for v in cls._LFSR_CONFIG:
            # Copy the configuration to create a new instance
            v = v.copy()
            # Set up the key for each LFSR generator
            v['key'] = key & (1 << 64) - 1

            # Instantiate an LFSR generator with the given configuration
            result.append(lfsr_ng(v))

        cls._lfsr_set_frame_num(result, frame_n)

        return result

    @staticmethod
    def _lfsr_get_bit(state):
        """Get one bit from each LFSR generator in the
        state list and XOR them to get the output bit"""

        result = 0
        bits = []
        # Store the generators according to their sync_bits (0 or 1)
        store = [[], []]
        for s in state:
            result ^= s.get_current_bit()

            t_bit = s.get_sync_bit()
            bits.append(t_bit)
            store[t_bit].append(s)

        # Update generators whose value corresponds with major state
        for s in store[calc_major(bits)]:
            s.next()

        return result

    @classmethod
    def process(cls, cipher_config, data, size=None):
        # If size is not provided, calculate it from the length of the given data
        if size is None:
            size = share.bin_len(data)

        # Initialize frame counter
        frame_cnt = 0
        # Initialize LFSR generator
        state = cls._lfsr_create(int(cipher_config['key']), frame_cnt)

        bits_cnt = 0
        for i in range(0, size):
            # XOR operation between bit from LFSR and the corresponding data bit
            # at position 'i'
            data ^= cls._lfsr_get_bit(state) << i

            # Every 114 bits (or 1 frame), increment frame counter and update
            # LFSR generator state
            if bits_cnt > 114:
                frame_cnt += 1
                bits_cnt = 0
                cls._lfsr_set_frame_num(state, frame_cnt)

            bits_cnt += 1

        return data

    @classmethod
    def encrypt(cls, cipher_config, message, alphabet):
        data, size = share.text_to_bin(message, alphabet)

        return cls.process(cipher_config, data, size)

    @classmethod
    def decrypt(cls, cipher_config, ciphertext, alphabet, size=None):
        result = cls.process(cipher_config, int(ciphertext), size)

        return share.bin_to_text(result, alphabet)

a5_1._MODULE_CAPABILITIES = {
	'enc': a5_1.encrypt,
	'dec': a5_1.decrypt,
}

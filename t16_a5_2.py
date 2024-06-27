from lfsr import lfsr_ng
import share

class a5_2:
    _MODULE_NAME = 'Шифр А5/2'
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
            'major_bits': [12, 14, 15],
            # Synchronization bit position
            'sync_bit': 10,
        },
        {
            'length': 22,
            'tapped_bits': [20, 21],
            'major_bits': [9, 13, 16],
            'sync_bit': 3,
        },
        {
            'length': 23,
            'tapped_bits': [7, 20, 21, 22],
            'major_bits': [13, 16, 18],
            'sync_bit': 7,
        }
    ]
    _CLOCK_CONFIG = {
        'length': 17,
        'key': 0b10010001000,
        # Tapped bits used in feedback function for the clock
        'tapped_bits': [11, 16],
        'major_bits': [3, 7, 10],
        'sync_bit': 0,
    }

    @classmethod
    def _lfsr_set_frame_num(cls, state, n):
        """Set frame number for all the LFSR generators in a state list"""
        for s in state:
            s.update_frame_num(n)

        # Create major bit generator
        clock = lfsr_ng(cls._CLOCK_CONFIG.copy())
        for _ in range(99):
            cls._lfsr_get_bit(state, clock)

        return clock

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

        # Update clock generator
        clock = cls._lfsr_set_frame_num(result, frame_n)

        return result, clock

    @staticmethod
    def _lfsr_get_bit(state, clock):
        """Get one bit from each LFSR generator in the
        state list and XOR them to get the output bit"""

        result = 0
        # Get current clock major bit
        major_bit = clock.get_major_bit()
        for s in state:
            result ^= s.get_current_bit()
            result ^= s.get_major_bit()

            # Shift LFSR generator state if it's value correspoonds with major bit
            if major_bit == clock.get_bit(s.get_sync_n()):
                s.next()

        # Shift clock state
        clock.next()

        return result

    @classmethod
    def process(cls, cipher_config, data, size=None):
        # If size is not provided, calculate it from the length of the given data
        if size is None:
            size = share.bin_len(data)

        # Initialize frame counter
        frame_cnt = 0
        # Initialize LFSR generator with major bit generator
        state, clock = cls._lfsr_create(int(cipher_config['key']), frame_cnt)

        bits_cnt = 0
        for i in range(size):
            # XOR operation between bit from LFSR and the corresponding data bit
            # at position 'i'
            data ^= cls._lfsr_get_bit(state, clock) << i

            # Every 114 bits (or 1 frame), increment frame counter and update
            # LFSR generator state
            if bits_cnt > 114:
                frame_cnt += 1
                bits_cnt = 0
                clock = cls._lfsr_set_frame_num(state, frame_cnt)

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

a5_2._MODULE_CAPABILITIES = {
	'enc': a5_2.encrypt,
	'dec': a5_2.decrypt,
}

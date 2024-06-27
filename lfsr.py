def calc_major(bits):
    cnt = len(bits)
    result = 0
    for i in range(cnt):
        for j in range(i + 1, cnt):
            result |= bits[i] & bits[j]

    return result

class lfsr_ng:
    def __init__(self, cipher_config):
        self._state = 0
        self._key = int(cipher_config['key'])
        self._length = int(cipher_config['length'])
        self._tapped_bits = cipher_config['tapped_bits']
        self._major_bits = cipher_config['major_bits']
        self._sync_bit = int(cipher_config['sync_bit'])

        self._select_mask = (1 << self._length) - 1

        t_key = self._key
        for _ in range(64):
            self._state ^= t_key & 1
            t_key >>= 1
            self.next()

        self._pre_frame_state = self._state

    def update_frame_num(self, n):
        self._state = self._pre_frame_state

        for _ in range(22):
            self._state ^= n & 1
            n >>= 1
            self.next()

    def get_sync_bit(self):
        return self._state >> self._sync_bit & 1

    def get_sync_n(self):
        return self._sync_bit

    def get_major_bit(self):
        bits = []
        for v in self._major_bits:
            bits.append(self._state >> v & 1)

        return calc_major(bits)

    def get_current_bit(self):
        return (self._state >> (self._length - 1)) & 1

    def get_bit(self, n):
        return self._state >> n & 1

    def next(self):
        new_bit = 0
        for v in self._tapped_bits:
            new_bit ^= self._state >> v & 1

        self._state <<= 1
        self._state |= new_bit
        self._state &= self._select_mask

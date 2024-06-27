import share
from cryprime import modpow, ressol

class ECC:
    def __init__(self, x, y, a, b, p, q=None, i=1):
        self._x = x
        self._y = y
        self._a = a
        self._b = b
        self._p = p
        self._q = q
        self._i = i
        self._is_zero = False
        #self._is_zero = (y == ((-y) % p))

        #if self.get_discriminant() == 0:
        #	raise RuntimeError('Invalid elliptic curve. Discriminant equals to 0')

    def __add__(self, o):
        r = self.get_clone()

        if r.x == o.x and r.y == o.y and r.y != 0:
            return r.double()

        u = (o.y - r.y) % r.p
        d = (o.x - r.x) % r.p
        lmd = (u * modpow(d, r.p - 2, r.p)) % r.p

        x = (lmd ** 2 - r.x - o.x) % r.p
        y = (lmd * (r.x - x) - r.y) % r.p

        is_zero = r.x == o.x and r.y == (-o.y) % r.p

        r._x = x
        r._y = y
        r._i += o._i
        r._is_zero = is_zero

        return r

    def double(self):
        u = (3 * self.x ** 2 + self.a) % self.p
        d = (2 * self.y) % self.p
        lmd = (u * modpow(d, self.p - 2, self.p)) % self.p

        x = (lmd ** 2 - self.x * 2) % self.p
        y = (lmd * (self.x - x) - self.y) % self.p

        #is_zero = self.y == (-self.y) % self.p

        self._x = x
        self._y = y
        self._i *= 2
        #self._is_zero = is_zero

        return self

    def is_on_ec(self):
        y_2 = (self.x ** 3 + self.a * self.x + self.b) % self.p
        by_2 = (self.y ** 2) % self.p

        return by_2 == y_2

    @property
    def q(self):
        if not self._q is None:
            return self._q

        q = 0
        for x in range(self.p):
            y_2 = (x ** 3 + self.a * x + self.b) % self.p

            y_r = ressol(y_2, self.p)

            if len(y_r) == 0:
                continue

            q += 1 + int(y_r[0] != y_r[1])

        q += 1
        if not share.is_prime(q):
            q = q // list(share.factorization(q, 1).keys())[-1]

        return q

    def from_x(self, x):
        y_2 = (x ** 3 + self.a * x + self.b) % self.p

        y = ressol(y_2, self.p)
        if len(y) == 0:
            return None

        return self.get_clone(x, y[0])

    def to_n(self, n, preserve_i=False):
        #if self.i != 1:
        #	raise RuntimeError('Unable to the power of n')

        if n <= 0:
            raise RuntimeError('n must be positive')

        v = self.get_clone()
        r = None
        while n > 0:
            if n & 1:
                if r is None:
                    r = v.get_clone()
                else:
                    r += v
            #else:
                # pass
            n >>= 1
            v.double()

        if preserve_i:
            return r

        return r.reset_increment()

    def get_invariant(self):
        return share.eea(
            self.get_discriminant(),
            (1728 * 4 * (self.a % self.p) ** 3),
            self.p
        )

    def get_discriminant(self):
        return (4 * self.a ** 3 + 27 * self.b ** 2) % self.p

    def get_clone(self, x=None, y=None):
        x_n = (x, self.x)[x is None]
        y_n = (y, self.y)[y is None]

        ec = ECC(
            x_n,
            y_n,
            self.a,
            self.b,
            self.p,
            self._q,
            self.i
        )

        if x is None and y is None:
            ec._is_zero = self.is_zero

        return ec

    def reset_increment(self):
        self._i = 1

        return self

    def values(self):
        return (self.x, self.y)

    @staticmethod
    def from_object(data):
        return ECC(
            data['x'],
            data['y'],
            data['a'],
            data['b'],
            data['p'],
            data['q'] if 'q' in data and int(data['q'] or 0) > 0 else None,
        )

    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y

    @property
    def a(self):
        return self._a

    @property
    def b(self):
        return self._b

    @property
    def p(self):
        return self._p

    @property
    def i(self):
        return self._i

    @property
    def is_zero(self):
        return self._is_zero

    def dump(self):
        return {
            'x': self.x,
            'y': self.y,
            'a': self.a,
            'b': self.b,
            'p': self.p,
            'q': self.q,
        }

    def __contains__(self, index):
        return hasattr(self, f'_{index}')

    def __getitem__(self, index):
        if isinstance(index, int):
            return self.to_n(index)
        else:
            return getattr(self, f'_{index}')

    def __str__(self):
        return f'({self.x}, {self.y}){("", "*")[self.is_zero]}'

    def __repr__(self):
        return f'[{hex(id(self))}]{str(self)}'

    def __len__(self):
        return len(str(self))

    def __format__(self, format_spec):
        return str(self)

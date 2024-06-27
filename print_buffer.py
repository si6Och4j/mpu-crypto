import functools
import sys

class BColor:
    class B:
        BLACK     = "\033[40m"
        RED       = "\033[41m"
        GREEN     = "\033[42m"
        YELLOW    = "\033[43m"
        BLUE      = "\033[44m"
        PURPLE    = "\033[45m"
        TURQUOISE = "\033[46m"
        WHITE     = "\033[47m"


    class T:
        BLACK     = "\033[30m"
        RED       = "\033[31m"
        GREEN     = "\033[32m"
        YELLOW    = "\033[33m"
        BLUE      = "\033[34m"
        PURPLE    = "\033[35m"
        TURQUOISE = "\033[36m"
        WHITE     = "\033[37m"


    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    ITALIC = "\033[3m"
    UNDER  = "\033[4m"
    RBLINK = "\033[5m"
    FBLINK = "\033[6m"
    FLIP   = "\033[7m"


class DefaultBuffer:
    def __init__(self, parent=None, no_indent=False, _in_g=False):
        self._buffer = []
        self._parent = parent
        self.no_indent = no_indent
        self._in_g = _in_g

    def __len__(self):
        return len(self._buffer)

    def _get_buffer(self):
        return []

    def add(self, *data, color=None):
        self.update_g()

        for i in data:
            if color is not None and isinstance(i, str):
                i = color + i + BColor.RESET

            self._buffer.append(i)

    def pop(self, n=1):
        self.update_g()
        if len(self._buffer) < n:
            return

        for _ in range(n):
            self._buffer.pop()

    def clear(self):
        self.update_g()
        self._buffer.clear()

    def to_callback(self, callback, *args, **kwargs):
        callback(self.to_str(), *args, **kwargs)

    def get_parent(self):
        return self._parent

    def update_g(self):
        if self._in_g:
            return GBuffer._set_root(self)

        return False

    def to_str(self, l=0):
        c = 0
        result = ""
        for i in self._get_buffer():
            if isinstance(i, DefaultBuffer):
                result += i.to_str((l + 1, l)[i.no_indent])
            else:
                result += "    " * (l - 1) + str(i) + "\n"

            c += 1

        return result


class SBuffer(DefaultBuffer):
    def _get_buffer(self):
        for i in self._buffer:
            yield i

    def gsb(self, no_indent=False, **kwargs):
        i = SBuffer(self, no_indent, self._in_g, **kwargs)
        self.add(i)

        return i

    def glb(self, no_indent=False, **kwargs):
        i = LBuffer(self, no_indent, self._in_g, **kwargs)
        self.add(i)

        return i


class GBuffer:
    _inst_list = {}

    def __init__(self):
        raise RuntimeError('G-buffer is static only')

    @classmethod
    def _i(cls, name):
        if not name in cls._inst_list:
            i = SBuffer(_in_g=True)
            cls._inst_list[name] = [i, i]

        return cls._inst_list[name]

    @classmethod
    def _set_root(cls, root):
        if not isinstance(root, SBuffer):
            return False

        cls._i(__name__)[1] = root

        return True

    @classmethod
    def add(cls, *args, **kwargs):
        return cls._i(__name__)[0].add(*args, **kwargs)

    @classmethod
    def pop(cls, *args, **kwargs):
        return cls._i(__name__)[0].pop(*args, **kwargs)

    @classmethod
    def clear(cls, *args, **kwargs):
        return cls._i(__name__)[0].clear(*args, **kwargs)

    @classmethod
    def to_callback(cls, *args, **kwargs):
        return cls._i(__name__)[0].to_callback(*args, **kwargs)

    @classmethod
    def gsb(cls, *args, **kwargs):
        i = cls._i(__name__)
        i[1] = i[1].gsb(*args, **kwargs)

        return i[1]

    @classmethod
    def glb(cls, *args, **kwargs):
        return cls._i(__name__)[1].glb(*args, **kwargs)

    @classmethod
    def __str__(cls):
        return cls._i(__name__)[0].__str__()

    @classmethod
    def get_all(cls):
        result = ''
        for i in cls._inst_list:
            result += str(i)

        return result

    @classmethod
    def wrap(cls, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            i = GBuffer.gsb()
            i.add(
                f'{func.__qualname__} | args: {str(args)}',
                color=BColor.T.GREEN
            )

            if '_sb' not in kwargs:
                kwargs['_sb'] = i

            silent = '_sb_silent' in kwargs
            if silent:
                del kwargs['_sb_silent']

            try:
                result = func(*args, **kwargs)
            except Exception as e:
                if hasattr(e, "_sb_accounted"):
                    raise e

                GBuffer.add(
                    'CATCH EXCEPTION. PRINING CURRENT BUFFER',
                    color=BColor.T.RED
                )
                GBuffer.add(str(e), color=BColor.T.RED)
                GBuffer.to_callback(print, file=sys.stderr)
                e._sb_accounted = True

                raise e

            parent = i.get_parent()
            parent.update_g()
            if silent:
                parent.pop()

            return result

        return wrapper

    @classmethod
    def print(cls):
        cls._i(__name__)[0].to_callback(print)


class LBuffer(DefaultBuffer):
    def __init__(self, *args, **kwargs):
        self.separator = '    '

        if 'separator' in kwargs:
            self.separator = kwargs['separator']
            del kwargs['separator']

        super().__init__(*args, **kwargs)

    def get_max_len(self):
        global_max = -1
        for i in self._buffer:
            local_max = max([len(str(c)) for c in i])
            if local_max > global_max:
                global_max = local_max

        return global_max

    def _get_buffer(self):
        alignment = self.get_max_len()

        for i in self._buffer:
            yield (
                '{:<{width}}{separator}' * len(i)
            ).format(*i, width=alignment, separator=self.separator)

    def fill_with_data(self, data, n, m, generator):
        for i in self.format_block_nm(data, n, m, generator):
            self.add(i)

    @staticmethod
    def format_block_nm(data, n, m, generator):
        tr = []
        result = []
        for i in generator(data, n):
            if len(tr) >= m:
                result.append(tr)
                tr = []

            tr.append(i)

        result.append(tr)

        return result

    @staticmethod
    def format_generator_Nint(data, n):
        tolen = len(str(max(data)))

        return LBuffer.format_generator_str(
            ["0" * (tolen - len(str(val))) + str(val) for val in data],
            n
        )

    @staticmethod
    def format_generator_str(data, n):
        if isinstance(data, list):
            data = ''.join(data)
        else:
            data = str(data)

        for i in range(0, len(data), n):
            yield str(data[i:i+n])

    # Обратная совместимость
    @staticmethod
    def print_blocks(data, callback):
        for i in data:
            callback(' '.join(i))

    @staticmethod
    def print_blocks_n_m(text, n, m):
        blocks = LBuffer.format_block_nm(
            text,
            n,
            m,
            LBuffer.format_generator_str
        )
        LBuffer.print_blocks(blocks, print)

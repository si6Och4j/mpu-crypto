from cryprime import modpow

class LCG:
    # Выдаёт "рабочие" значения, но не соответствует ГОСТ
    class b512:
        @staticmethod
        def gen(t, x, c):
            x_len = 16
            # x_len = 32
            gen_mul = 19381
            # gen_mul = 97781173

            t = [t]
            while t[-1] >= (x_len + 1):
                t.append(round(t[-1] / 2))

            s = len(t) - 1
            m = s - 1

            y_s = [x]
            p = t.copy()

            exp = 2 ** x_len
            # expT = 2 ** (x_len * 10 + 1)
            while m >= 0:
                r_m = t[m + 1] // x_len
                for i in range(r_m):
                    y_s.append((gen_mul * y_s[-1] + c) % exp)

                Y = 0
                for i in range(r_m - 1):
                    Y += y_s[i] * exp

                y_s = [y_s[r_m]]

                N1 = 2 ** (t[m] - 1) // p[m + 1]
                N2 = round((2 ** (t[m] - 1) * Y) / (p[m + 1] * 2 ** (x_len * r_m)))
                N = N1 + N2
                if N % 2 == 1:
                    N += 1

                k = 0
                pass_cond = False
                while not pass_cond:
                    p[m] = p[m + 1] * (N + k) + 1
                    if p[m] > 2 ** t[m]:
                        m += 1
                        break

                    pass_cond = modpow(2, p[m + 1] * (N + k), p[m]) == 1
                    pass_cond &= modpow(2, N + k, p[m]) != 1
                    k += 2

                m -= 1

            return p

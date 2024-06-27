import share
from ecc import ECC
from ecc_ext import points_group
from print_buffer import GBuffer

sb = GBuffer.gsb()
c = ECC(7, 36, 1, 3, 41)
a = ECC(26, 4, 1, 3, 41)

sb.add(a[3])

sb.add('TASK №1')
dis = a.get_discriminant()
inv = a.get_invariant()
sb.pop(2)

sb.add(f'Discriminant: {dis}')
sb.add(f'J-Invariant: {inv}')
#sb.add(f'q: {a.q}')

sb.add('TASK №2')
sb.add('EC points')
points = []
for ps in points_group(a):
#	sb.pop(2)
    for p in ps:
        sb.add(str(p))
        points.append(p)

sb.add('TASK №3')
sb.add('Points map')
lb = sb.glb(True, separator=';')
for i in range(1, a.p):
    row_points = []
    for p in points:
        p_i = p.to_n(i, True)
        #sb.pop()
        row_points.append(p_i)

        if p_i.is_zero and not hasattr(p, "zero_i"):
            p.zero_i = p_i.i

    lb.add(row_points)


sb.add('TASK №4')
sb.add('Point\'s order')
prime_orders = []
for p in points:
    if not hasattr(p, 'zero_i'):
        continue

    sb.add(f'{str(p)} - {p.zero_i}')
    if p.zero_i > 2 and share.is_prime(p.zero_i):
        prime_orders.append(p)
    sb.pop()

sb.add('TASK №5')
sb.add('Points with prime order:')
for p in prime_orders:
    sb.add(f'{str(p)} - {p.zero_i}')

GBuffer.to_callback(print)

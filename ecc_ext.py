from cryprime import ressol

def points_group(self):
    for x in range(0, self.p):
        y_2 = (x ** 3 + self.a * x + self.b) % self.p

        y = ressol(y_2, self.p)

        if len(y) == 0:
            continue

        r = [self.get_clone(x, y[0])]
        if y[0] != y[1]:
            r.append(self.get_clone(x, y[1]))

        yield r

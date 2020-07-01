from z3 import *
a0,a1,a2,a3,a4,a5 = BitVecs('a0 a1 a2 a3 a4 a5',64)
fucker = Solver()
fucker.add(a2 - a3 == 2225223423)
fucker.add(a3 + a4 == 4201428739)
fucker.add(a2 - a4 == 1121399208)
fucker.add(a0 == 3746099070)
fucker.add(a5 == 2230518816)
fucker.add(a1 == 550153460)

print(fucker.check())
print(fucker.model())
from z3 import *
s = Solver()
a,b,c = BitVecs('a b c',32) 
s.add((((a>>4))*0x15-c==0x1d7ecc6b))
s.add(((c>>8))*3+b==0x6079797c)
s.add(((a>>8))+b==0x5fbcbdbd)
s.add(a&0xff==0x5e)
s.add(b&0x0ff0000==0x5e0000)
s.add(a&0xff==0x5e)
print(s.check())
print(s.model())
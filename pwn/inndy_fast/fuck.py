from pwn import *
r = remote('node3.buuoj.cn',29649)
r.recvuntil('game.')
r.sendline('Yes I know')
from numpy import int32

ans = ''
res = ''

f = lambda x: int32(int(x))
for i in xrange(10000):
    n1, op, n2 = r.recvuntil("=", drop = True).strip().split(' ')
    r.recvline()
    if op == '+':
        ans = str(f(n1) + f(n2))
    if op == '-':
        ans = str(f(n1) - f(n2))
    if op == '*':
        ans = str(f(n1) * f(n2))
    if op == '/':
        ans = str(int(float(n1) / int(n2)))

    res += (ans + ' ')

r.sendline(res)
r.interactive()
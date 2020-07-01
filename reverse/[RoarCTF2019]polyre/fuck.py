fuck = [0xBC8FF26D43536296, 0x520100780530EE16, 0x4DC0B5EA935F08EC, 0x342B90AFD853F450, 0x8B250EBCAA2C3681, 0x55759F81A2C68AE4]
flag = ''
for s in fuck:
    for i in range(64):
        sign = s & 1
        if sign == 1:
            s ^= 0xB0004B7679FA26B3
        s //= 2
        if sign == 1:
            s |= 0x8000000000000000
    print(hex(s))
    j = 0
    while j < 8:
        flag += chr(s&0xFF)
        s >>= 8
        j += 1
print(flag)
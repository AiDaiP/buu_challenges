import base64
enc = 'e3nifIH9b_C@n@dH'
flag = ''
for i in range(len(enc)):
    flag += chr(ord(enc[i]) - i)

flag = base64.b64decode(flag)
print(flag)
def encrypt(plainText):
    space = 10
    cipherText = ""
    for i in range(len(plainText)):
        if i + space < len(plainText) - 1:
            cipherText += chr(ord(plainText[i]) ^ ord(plainText[i + space]))
        else:
            cipherText += chr(ord(plainText[i]) ^ ord(plainText[space]))
        if ord(plainText[i]) % 2 == 0:
            space += 1
        else:
            space -= 1
    return cipherText
   

# 15120d1a0a0810010a031d3e31000d1d170d173b0d173b0c07060206

c = '15120d1a0a0810010a031d3e31000d1d170d173b0d173b0c07060206'.decode('hex')

while True:
    c = encrypt(c)
    if 'afctf' in c:
        print(c)
        break
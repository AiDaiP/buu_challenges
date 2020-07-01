import base64
f1 = open('crypt_info.txt','r')
info_enc = f1.read()
clear_info = 'There are so many people around me doing small job but they impress me so much.'

fuck = 'U2FsdGVkX1/vU5MhjDoz+ioydw0D29dDIUULWF+MPtPTI8jSqoEdDVAAIrutPjzDegvSVodD3x8='
flag_enc = base64.b64decode(fuck)
print(flag_enc)
print(flag_enc.encode('hex'))
print(len(flag_enc))

def str_xor(a,b):
	res = ''
	for i in range(len(a)):
		res += chr(ord(a[i])^ord(b[i]))
	return res

print(str_xor(clear_info,info_enc))
key = 'BECauSE yOU sAId 10,000 TImE OF mELaNCHOLY.ThiS TrUe IS jOYfUL pOSSIblY iS LasT'
key = 'BECSEOUAI10,000TIEOFELNCHOLY.TSTUISOYULOSSIYSLT'
print(len(key))
	
print(str_xor(flag_enc,key))
from hashlib import sha1,md5
for i in range(100000):
	if sha1(str(i)).hexdigest() == 'DD01903921EA24941C26A48F2CEC24E0BB0E8CC7'.lower():
		print(i)
		print(md5(str(i)).hexdigest().upper()[:20])
		break
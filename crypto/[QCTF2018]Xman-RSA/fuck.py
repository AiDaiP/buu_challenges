from gmpy2 import is_prime
from os import urandom
import base64

'''def separate(n):
	p = n % 4
	t = (p*p) % 4
	return t == 1

f = open('flag.txt', 'r')
flag = f.read()

msg1 = ""
msg2 = ""
for i in range(len(flag)):
	if separate(i):
		msg2 += flag[i]
	else:
		msg1 += flag[i]'''

p1 = get_a_prime(128)
p2 = get_a_prime(128)
p3 = get_a_prime(128)
n1 = p1*p2
n2 = p1*p3
e = 0x1001
c1 = encrypt(msg1, e, n1)
c2 = encrypt(msg2, e, n2)
print(c1)
print(c2)

e1 = 0x1001
e2 = 0x101

n1 = 'PVNHb2BfGAnmxLrbKhgsYXRwWIL9eOj6K0s3I0slKHCTXTAUtZh3T0r+RoSlhpO3+77AY8P7WETYz2Jzuv5FV/mMODoFrM5fMyQsNt90VynR6J3Jv+fnPJPsm2hJ1Fqt7EKaVRwCbt6a4BdcRoHJsYN/+eh7k/X+FL5XM7viyvQxyFawQrhSV79FIoX6xfjtGW+uAeVF7DScRcl49dlwODhFD7SeLqzoYDJPIQS+VSb3YtvrDgdV+EhuS1bfWvkkXRijlJEpLrgWYmMdfsYX8u/+Ylf5xcBGn3hv1YhQrBCg77AHuUF2w/gJ/ADHFiMcH3ux3nqOsuwnbGSr7jA6Cw=='
n2 = 'TmNVbWUhCXR1od3gBpM+HGMKK/4ErfIKITxomQ/QmNCZlzmmsNyPXQBiMEeUB8udO7lWjQTYGjD6k21xjThHTNDG4z6C2cNNPz73VIaNTGz0hrh6CmqDowFbyrk+rv53QSkVKPa8EZnFKwGz9B3zXimm1D+01cov7V/ZDfrHrEjsDkgK4ZlrQxPpZAPl+yqGlRK8soBKhY/PF3/GjbquRYeYKbagpUmWOhLnF4/+DP33ve/EpaSAPirZXzf8hyatL4/5tAZ0uNq9W6T4GoMG+N7aS2GeyUA2sLJMHymW4cFK5l5kUvjslRdXOHTmz5eHxqIV6TmSBQRgovUijlNamQ=='
n1 = bytes_to_long(base64.b64encode(n2))
n2 = bytes_to_long(base64.b64encode(n3))
print(n1)
print(n2)
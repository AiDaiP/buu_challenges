from z3 import *

def fuck():
	out = [8886,42,212351850074573251730471044,424970871445403036476084342,5074088654060645719700112791577634658478525829848,17980375751459479892183878405763572663247662296,121243943296116422476619559571200060016769222670118557978266602062366168,242789433733772377162253757058605232140494788666115363337105327522154016,2897090450760618154631253497246288923325478215090551806927512438699802516318766105962219562904,7372806106688864629183362019405317958359908549913588813279832042020854419620109770781392560]
	plaintext = "Houdini:"
	for i in range(8):
		print('s.add('+'(('+str(out[i+1])+'+('+str((out[i] * ord(plaintext[i])))+'^key+'+str(out[i+1])+'))) ^ (key*'+str(out[i])+')'+'=='+str(out[i+2])+')')

def decrypt(ciphertext,key):
	out = ciphertext
	plaintext = ''
	for i in range(2,len(ciphertext)):
		plaintext += chr((((out[i] ^ (key*out[i-2])) - out[i-1]) ^ (key+out[i-1]))//out[i-2])
	return plaintext

key = BitVec('key',77)
s = Solver()
s.add(((42+(639792^key+42))) ^ (key*8886)==212351850074573251730471044)
s.add(((212351850074573251730471044+(4662^key+212351850074573251730471044))) ^ (key*42)==424970871445403036476084342)
s.add(((424970871445403036476084342+(24845166458725070452465112148^key+424970871445403036476084342))) ^ (key*212351850074573251730471044)==5074088654060645719700112791577634658478525829848)
s.add(((5074088654060645719700112791577634658478525829848+(42497087144540303647608434200^key+5074088654060645719700112791577634658478525829848))) ^ (key*424970871445403036476084342)==17980375751459479892183878405763572663247662296)
s.add(((17980375751459479892183878405763572663247662296+(532779308676367800568511843115651639140245212134040^key+17980375751459479892183878405763572663247662296))) ^ (key*5074088654060645719700112791577634658478525829848)==121243943296116422476619559571200060016769222670118557978266602062366168)
s.add(((121243943296116422476619559571200060016769222670118557978266602062366168+(1977841332660542788140226624633992992957242852560^key+121243943296116422476619559571200060016769222670118557978266602062366168))) ^ (key*17980375751459479892183878405763572663247662296)==242789433733772377162253757058605232140494788666115363337105327522154016)
s.add(((242789433733772377162253757058605232140494788666115363337105327522154016+(12730614046092224360045053754976006301760768380362448587717993216548447640^key+242789433733772377162253757058605232140494788666115363337105327522154016))) ^ (key*121243943296116422476619559571200060016769222670118557978266602062366168)==2897090450760618154631253497246288923325478215090551806927512438699802516318766105962219562904)
s.add(((2897090450760618154631253497246288923325478215090551806927512438699802516318766105962219562904+(14081787156558797875410717909399103464148697742634691073552108996284932928^key+2897090450760618154631253497246288923325478215090551806927512438699802516318766105962219562904))) ^ (key*242789433733772377162253757058605232140494788666115363337105327522154016)==7372806106688864629183362019405317958359908549913588813279832042020854419620109770781392560)
s.check()
print(s.model())
key = 23894723084723483784384
flag = ''
msg = open('conversation','rb').readlines()
for i in range(1,len(msg),2):
	tmp = map(int,msg[i].replace('Content: ','').split(' '))
	flag += decrypt(tmp,key)
	print(flag)
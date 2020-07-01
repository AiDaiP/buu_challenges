import itertools
key = []
c = 'ouauuuoooeeaaiaeauieuooeeiea'
for i in itertools.permutations('aeiou', 5):
    key = ''.join(i)
    temp_c = ''
    flag = ''
    for temp in c:
        temp_c += str(key.index(temp))         
    for i in range(0,len(temp_c),2):
        current_ascii = int(temp_c[i])*5+int(temp_c[i+1])+97     
        if current_ascii>ord('i'):
            current_ascii+=1
        flag += chr(current_ascii)
    if 'flag' in flag:
        print(key,flag)

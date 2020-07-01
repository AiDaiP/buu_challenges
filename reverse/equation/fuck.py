import re
 
from z3 import *
if __name__ =="__main__":
	s = Solver()
 
	l = [Int('l%d'%i) for i in range(0x2a)]
	for i in l:
		s.add(0<i)
		s.add(i<256)
	s.add(l[40] + l[35] + l[34] - l[0] - l[15] - l[37] + l[7] + l[6] - l[26] + l[20] + l[19] + l[8] - l[17] - l[14] - l[38] + l[1] - l[9] + l[22] + l[41] + l[3] - l[29] - l[36] - l[25] + l[5] + l[32] - l[16] + l[12] - l[24] + l[30] + l[39] + l[10] + l[2] + l[27] + l[28] + l[21] + l[33] - l[18] + l[4] == 861)
	s.add(l[31] + l[26] + l[11] - l[33] + l[27] - l[3] + l[12] + l[30] + l[1] + l[32] - l[16] + l[7] + l[10] - l[25] + l[38] - l[41] - l[14] - l[19] + l[29] + l[36] - l[9] - l[28] - l[6] - l[0] - l[22] - l[18] + l[20] - l[37] + l[4] - l[24] + l[34] - l[21] - l[39] - l[23] - l[8] - l[40] + l[15] - l[35] == -448)
	s.add(l[26] + l[14] + l[15] + l[9] + l[13] + l[30] - l[11] + l[18] + l[23] + l[7] + l[3] + l[12] + l[25] - l[24] - l[39] - l[35] - l[20] + l[40] - l[8] + l[10] - l[5] - l[33] - l[31] + l[32] + l[19] + l[21] - l[6] + l[1] + l[16] + l[17] + l[29] + l[22] - l[4] - l[36] + l[41] + l[38] + l[2] + l[0] == 1244)
	s.add(l[5] + l[22] + l[15] + l[2] - l[28] - l[10] - l[3] - l[13] - l[18] + l[30] - l[9] + l[32] + l[19] + l[34] + l[23] - l[17] + l[16] - l[7] + l[24] - l[39] + l[8] - l[12] - l[40] - l[25] + l[37] - l[35] + l[11] - l[14] + l[20] - l[27] + l[4] - l[33] - l[21] + l[31] - l[6] + l[1] + l[38] - l[29] == -39)
	s.add(l[41] - l[29] + l[23] - l[4] + l[20] - l[33] + l[35] + l[3] - l[19] - l[21] + l[11] + l[26] - l[24] - l[17] + l[37] + l[1] + l[16] - l[0] - l[13] + l[7] + l[10] + l[14] + l[22] + l[39] - l[40] + l[34] - l[38] + l[32] + l[25] - l[2] + l[15] + l[6] + l[28] - l[8] - l[5] - l[31] - l[30] - l[27] == 485)
	s.add(l[13] + l[19] + l[21] - l[2] - l[33] - l[0] + l[39] + l[31] - l[23] - l[41] + l[38] - l[29] + l[36] + l[24] - l[20] - l[9] - l[32] + l[37] - l[35] + l[40] + l[7] - l[26] + l[15] - l[10] - l[6] - l[16] - l[4] - l[5] - l[30] - l[14] - l[22] - l[25] - l[34] - l[17] - l[11] - l[27] + l[1] - l[28] == -1068)
	s.add(l[32] + l[0] + l[9] + l[14] + l[11] + l[18] - l[13] + l[24] - l[2] - l[15] + l[19] - l[21] + l[1] + l[39] - l[8] - l[3] + l[33] + l[6] - l[5] - l[35] - l[28] + l[25] - l[41] + l[22] - l[17] + l[10] + l[40] + l[34] + l[27] - l[20] + l[23] + l[31] - l[16] + l[7] + l[12] - l[30] + l[29] - l[4] == 939)
	s.add(l[19] + l[11] + l[20] - l[16] + l[40] + l[25] + l[1] - l[31] + l[28] - l[23] + l[14] - l[9] - l[27] + l[35] + l[39] - l[37] - l[8] - l[22] + l[5] - l[6] + l[0] - l[32] + l[24] + l[33] + l[29] + l[38] + l[15] - l[2] + l[30] + l[7] + l[12] - l[3] - l[17] + l[34] + l[41] - l[4] - l[13] - l[26] == 413)
	s.add(l[22] + l[4] - l[9] + l[34] + l[35] + l[17] + l[3] - l[24] + l[38] - l[5] - l[41] - l[31] - l[0] - l[25] + l[33] + l[15] - l[1] - l[10] + l[16] - l[29] - l[12] + l[26] - l[39] - l[21] - l[18] - l[6] - l[40] - l[13] + l[8] + l[37] + l[19] + l[14] + l[32] + l[28] - l[11] + l[23] + l[36] + l[7] == 117)
	s.add(l[32] + l[16] + l[3] + l[11] + l[34] - l[31] + l[14] + l[25] + l[1] - l[30] - l[33] - l[40] - l[4] - l[29] + l[18] - l[27] + l[13] - l[19] - l[12] + l[23] - l[39] - l[41] - l[8] + l[22] - l[5] - l[38] - l[9] - l[37] + l[17] - l[36] + l[24] - l[21] + l[2] - l[26] + l[20] - l[7] + l[35] - l[0] == -313)
	s.add(l[40] - l[1] + l[5] + l[7] + l[33] + l[29] + l[12] + l[38] - l[31] + l[2] + l[14] - l[35] - l[8] - l[24] - l[39] - l[9] - l[28] + l[23] - l[17] - l[22] - l[26] + l[32] - l[11] + l[4] - l[36] + l[10] + l[20] - l[18] - l[16] + l[6] - l[0] + l[3] - l[30] + l[37] - l[19] + l[21] + l[25] - l[15] == -42)
	s.add(l[21] + l[26] - l[17] - l[25] + l[27] - l[22] - l[39] - l[23] - l[15] - l[20] - l[32] + l[12] + l[3] - l[6] + l[28] + l[31] + l[13] - l[16] - l[37] - l[30] - l[5] + l[41] + l[29] + l[36] + l[1] + l[11] + l[24] + l[18] - l[40] + l[19] - l[35] + l[2] - l[38] + l[14] - l[9] + l[4] + l[0] - l[33] == 289)
	s.add(l[29] + l[31] + l[32] - l[17] - l[7] + l[34] + l[2] + l[14] + l[23] - l[4] + l[3] + l[35] - l[33] - l[9] - l[20] - l[37] + l[24] - l[27] + l[36] + l[15] - l[18] - l[0] + l[12] + l[11] - l[38] + l[6] + l[22] + l[39] - l[25] - l[10] - l[19] - l[1] + l[13] - l[41] + l[30] - l[16] + l[28] - l[26] == -117)
	s.add(l[5] + l[37] - l[39] + l[0] - l[27] + l[12] + l[41] - l[22] + l[8] - l[16] - l[38] + l[9] + l[15] - l[35] - l[29] + l[18] + l[6] - l[25] - l[28] + l[36] + l[34] + l[32] - l[14] - l[1] + l[20] + l[40] - l[19] - l[4] - l[7] + l[26] + l[30] - l[10] + l[13] - l[21] + l[2] - l[23] - l[3] - l[33] == -252)
	s.add(l[29] + l[10] - l[41] - l[9] + l[12] - l[28] + l[11] + l[40] - l[27] - l[8] + l[32] - l[25] - l[23] + l[39] - l[1] - l[36] - l[15] + l[33] - l[20] + l[18] + l[22] - l[3] + l[6] - l[34] - l[21] + l[19] + l[26] + l[13] - l[4] + l[7] - l[37] + l[38] - l[2] - l[30] - l[0] - l[35] + l[5] + l[17] == -183)
	s.add(l[6] - l[8] - l[20] + l[34] - l[33] - l[25] - l[4] + l[3] + l[17] - l[13] - l[15] - l[40] + l[1] - l[30] - l[14] - l[28] - l[35] + l[38] - l[22] + l[2] + l[24] - l[29] + l[5] + l[9] + l[37] + l[23] - l[18] + l[19] - l[21] + l[11] + l[36] + l[41] - l[7] - l[32] + l[10] + l[26] - l[0] + l[31] == 188)
	s.add(l[3] + l[6] - l[41] + l[10] + l[39] + l[37] + l[1] + l[8] + l[21] + l[24] + l[29] + l[12] + l[27] - l[38] + l[11] + l[23] + l[28] + l[33] - l[31] + l[14] - l[5] + l[32] - l[17] + l[40] - l[34] + l[20] - l[22] - l[16] + l[19] + l[2] - l[36] - l[7] + l[18] + l[15] + l[26] - l[0] - l[4] + l[35] == 1036)
	s.add(l[28] - l[33] + l[2] + l[37] - l[12] - l[9] - l[39] + l[16] - l[32] + l[8] - l[36] + l[31] + l[10] - l[4] + l[21] - l[25] + l[18] + l[24] - l[0] + l[29] - l[26] + l[35] - l[22] - l[41] - l[6] + l[15] + l[19] + l[40] + l[7] + l[34] + l[17] - l[3] - l[13] + l[5] + l[23] + l[11] - l[27] + l[1] == 328)
	s.add(l[22] - l[32] + l[17] - l[9] + l[20] - l[18] - l[34] + l[23] + l[36] - l[35] - l[38] + l[27] + l[4] - l[5] - l[41] + l[29] + l[33] + l[0] - l[37] + l[28] - l[40] - l[11] - l[12] + l[7] + l[1] + l[2] - l[26] - l[16] - l[8] + l[24] - l[25] + l[3] - l[6] - l[19] - l[39] - l[14] - l[31] + l[10] == -196)
	s.add(l[11] + l[13] + l[14] - l[15] - l[29] - l[2] + l[7] + l[20] + l[30] - l[36] - l[33] - l[19] + l[31] + l[0] - l[39] - l[4] - l[6] + l[38] + l[35] - l[28] + l[34] - l[9] - l[23] - l[26] + l[37] - l[8] - l[27] + l[5] - l[41] + l[3] + l[17] + l[40] - l[10] + l[25] + l[12] - l[24] + l[18] + l[32] == 7)
	s.add(l[34] - l[37] - l[40] + l[4] - l[22] - l[31] - l[6] + l[38] + l[13] - l[28] + l[8] + l[30] - l[20] - l[7] - l[32] + l[26] + l[1] - l[18] + l[5] + l[35] - l[24] - l[41] + l[9] - l[0] - l[2] - l[15] - l[10] + l[12] - l[36] + l[33] - l[16] - l[14] - l[25] - l[29] - l[21] + l[27] + l[3] - l[17] == -945)
	s.add(l[12] - l[30] - l[8] + l[20] - l[2] - l[36] - l[25] - l[0] - l[19] - l[28] - l[7] - l[11] - l[33] + l[4] - l[23] + l[10] - l[41] + l[39] - l[32] + l[27] + l[18] + l[15] + l[34] + l[13] - l[40] + l[29] - l[6] + l[37] - l[14] - l[16] + l[38] - l[26] + l[17] + l[31] - l[22] - l[35] + l[5] - l[1] == -480)
	s.add(l[36] - l[11] - l[34] + l[8] + l[0] + l[15] + l[28] - l[39] - l[32] - l[2] - l[27] + l[22] + l[16] - l[30] - l[3] + l[31] - l[26] + l[20] + l[17] - l[29] - l[18] + l[19] - l[10] + l[6] - l[5] - l[38] - l[25] - l[24] + l[4] + l[23] + l[9] + l[14] + l[21] - l[37] + l[13] - l[41] - l[12] + l[35] == -213)
	s.add(l[19] - l[36] - l[12] + l[33] - l[27] - l[37] - l[25] + l[38] + l[16] - l[18] + l[22] - l[39] + l[13] - l[7] - l[31] - l[26] + l[15] - l[10] - l[9] - l[2] - l[30] - l[11] + l[41] - l[4] + l[24] + l[34] + l[5] + l[17] + l[14] + l[6] + l[8] - l[21] - l[23] + l[32] - l[1] - l[29] - l[0] + l[3] == -386)
	s.add(l[0] + l[7] - l[28] - l[38] + l[19] + l[31] - l[5] + l[24] - l[3] + l[33] - l[12] - l[29] + l[32] + l[1] - l[34] - l[9] - l[25] + l[26] - l[8] + l[4] - l[10] + l[40] - l[15] - l[11] - l[27] + l[36] + l[14] + l[41] - l[35] - l[13] - l[17] - l[21] - l[18] + l[39] - l[2] + l[20] - l[23] - l[22] == -349)
	s.add(l[10] + l[22] + l[21] - l[0] + l[15] - l[6] + l[20] - l[29] - l[30] - l[33] + l[19] + l[23] - l[28] + l[41] - l[27] - l[12] - l[37] - l[32] + l[34] - l[36] + l[3] + l[1] - l[13] + l[18] + l[14] + l[9] + l[7] - l[39] + l[8] + l[2] - l[31] - l[5] - l[40] + l[38] - l[26] - l[4] + l[16] - l[25] == 98)
	s.add(l[28] + l[38] + l[20] + l[0] - l[5] - l[34] - l[41] + l[22] - l[26] + l[11] + l[29] + l[31] - l[3] - l[16] + l[23] + l[17] - l[18] + l[9] - l[4] - l[12] - l[19] - l[40] - l[27] + l[33] + l[8] - l[37] + l[2] + l[15] - l[24] - l[39] + l[10] + l[35] - l[1] + l[30] - l[36] - l[25] - l[14] - l[32] == -412)
	s.add(l[1] - l[24] - l[29] + l[39] + l[41] + l[0] + l[9] - l[19] + l[6] - l[37] - l[22] + l[32] + l[21] + l[28] + l[36] + l[4] - l[17] + l[20] - l[13] - l[35] - l[5] + l[33] - l[27] - l[30] + l[40] + l[25] - l[18] + l[34] - l[3] - l[10] - l[16] - l[23] - l[38] + l[8] - l[14] - l[11] - l[7] + l[12] == -95)
	s.add(l[2] - l[24] + l[31] + l[0] + l[9] - l[6] + l[7] - l[1] - l[22] + l[8] - l[23] + l[40] + l[20] - l[38] - l[11] - l[14] + l[18] - l[36] + l[15] - l[4] - l[41] - l[12] - l[34] + l[32] - l[35] + l[17] - l[21] - l[10] - l[29] + l[39] - l[16] + l[27] + l[26] - l[3] - l[5] + l[13] + l[25] - l[28] == -379)
	s.add(l[19] - l[17] + l[31] + l[14] + l[6] - l[12] + l[16] - l[8] + l[27] - l[13] + l[41] + l[2] - l[7] + l[32] + l[1] + l[25] - l[9] + l[37] + l[34] - l[18] - l[40] - l[11] - l[10] + l[38] + l[21] + l[3] - l[0] + l[24] + l[15] + l[23] - l[20] + l[26] + l[22] - l[4] - l[28] - l[5] + l[39] + l[35] == 861)
	s.add(l[35] + l[36] - l[16] - l[26] - l[31] + l[0] + l[21] - l[13] + l[14] + l[39] + l[7] + l[4] + l[34] + l[38] + l[17] + l[22] + l[32] + l[5] + l[15] + l[8] - l[29] + l[40] + l[24] + l[6] + l[30] - l[2] + l[25] + l[23] + l[1] + l[12] + l[9] - l[10] - l[3] - l[19] + l[20] - l[37] - l[33] - l[18] == 1169)
	s.add(l[13] + l[0] - l[25] - l[32] - l[21] - l[34] - l[14] - l[9] - l[8] - l[15] - l[16] + l[38] - l[35] - l[30] - l[40] - l[12] + l[3] - l[19] + l[4] - l[41] + l[2] - l[36] + l[37] + l[17] - l[1] + l[26] - l[39] - l[10] - l[33] + l[5] - l[27] - l[23] - l[24] - l[7] + l[31] - l[28] - l[18] + l[6] == -1236)
	s.add(l[20] + l[27] - l[29] - l[25] - l[3] + l[28] - l[32] - l[11] + l[10] + l[31] + l[16] + l[21] - l[7] + l[4] - l[24] - l[35] + l[26] + l[12] - l[37] + l[6] + l[23] + l[41] - l[39] - l[38] + l[40] - l[36] + l[8] - l[9] - l[5] - l[1] - l[13] - l[14] + l[19] + l[0] - l[34] - l[15] + l[17] + l[22] == -114)
	s.add(l[12] - l[28] - l[13] - l[23] - l[33] + l[18] + l[10] + l[11] + l[2] - l[36] + l[41] - l[16] + l[39] + l[34] + l[32] + l[37] - l[38] + l[20] + l[6] + l[7] + l[31] + l[5] + l[22] - l[4] - l[15] - l[24] + l[17] - l[3] + l[1] - l[35] - l[9] + l[30] + l[25] - l[0] - l[8] - l[14] + l[26] + l[21] == 659)
	s.add(l[21] - l[3] + l[7] - l[27] + l[0] - l[32] - l[24] - l[37] + l[4] - l[22] + l[20] - l[5] - l[30] - l[31] - l[1] + l[15] + l[41] + l[12] + l[40] + l[38] - l[17] - l[39] + l[19] - l[13] + l[23] + l[18] - l[2] + l[6] - l[33] - l[9] + l[28] + l[8] - l[16] - l[10] - l[14] + l[34] + l[35] - l[11] == -430)
	s.add(l[11] - l[23] - l[9] - l[19] + l[17] + l[38] - l[36] - l[22] - l[10] + l[27] - l[14] - l[4] + l[5] + l[31] + l[2] + l[0] - l[16] - l[8] - l[28] + l[3] + l[40] + l[25] - l[33] + l[13] - l[32] - l[35] + l[26] - l[20] - l[41] - l[30] - l[12] - l[7] + l[37] - l[39] + l[15] + l[18] - l[29] - l[21] == -513)
	s.add(l[32] + l[19] + l[4] - l[13] - l[17] - l[30] + l[5] - l[33] - l[37] - l[15] - l[18] + l[7] + l[25] - l[14] + l[35] + l[40] + l[16] + l[1] + l[2] + l[26] - l[3] - l[39] - l[22] + l[23] - l[36] - l[27] - l[9] + l[6] - l[41] - l[0] - l[31] - l[20] + l[12] - l[8] + l[29] - l[11] - l[34] + l[21] == -502)
	s.add(l[30] - l[31] - l[36] + l[3] + l[9] - l[40] - l[33] + l[25] + l[39] - l[26] + l[23] - l[0] - l[29] - l[32] - l[4] + l[37] + l[28] + l[21] + l[17] + l[2] + l[24] + l[6] + l[5] + l[8] + l[16] + l[27] + l[19] + l[12] + l[20] + l[41] - l[22] + l[15] - l[11] + l[34] - l[18] - l[38] + l[1] - l[14] == 853)
	s.add(l[38] - l[10] + l[16] + l[8] + l[21] - l[25] + l[36] - l[30] + l[31] - l[3] + l[5] - l[15] + l[23] - l[28] + l[7] + l[12] - l[29] + l[22] - l[0] - l[37] - l[14] - l[11] + l[32] + l[33] - l[9] + l[39] + l[41] - l[19] - l[1] + l[18] - l[4] - l[6] + l[13] + l[20] - l[2] - l[35] - l[26] + l[27] == -28)
	s.add(l[11] + l[18] - l[26] + l[15] - l[14] - l[33] + l[7] - l[23] - l[25] + l[0] - l[6] - l[21] - l[16] + l[17] - l[19] - l[28] - l[38] - l[37] + l[9] + l[20] - l[8] - l[3] + l[22] - l[35] - l[10] - l[31] - l[2] + l[41] - l[1] - l[4] + l[24] - l[34] + l[39] + l[40] + l[32] - l[5] + l[36] - l[27] == -529)
	s.add(l[38] + l[8] + l[36] + l[35] - l[23] - l[34] + l[13] - l[4] - l[27] - l[24] + l[26] + l[31] - l[30] - l[5] - l[40] + l[28] - l[11] - l[2] - l[39] + l[15] + l[10] - l[17] + l[3] + l[19] + l[22] + l[33] + l[0] + l[37] + l[16] - l[9] - l[32] + l[25] - l[21] - l[12] + l[6] - l[41] + l[20] - l[18] == -12)
	s.add(l[6] - l[30] - l[20] - l[27] - l[14] - l[39] + l[41] - l[33] - l[0] + l[25] - l[32] - l[3] + l[26] - l[12] + l[8] - l[35] - l[24] + l[15] + l[9] - l[4] + l[13] + l[36] + l[34] + l[1] - l[28] - l[21] + l[18] + l[23] + l[29] - l[10] - l[38] + l[22] + l[37] + l[5] + l[19] + l[7] + l[16] - l[31] == 81)
 
 
	if s.check() ==sat:
		m = s.model()
		for i in range(0,0x2a):
			print(chr(int("%s" % (m[l[i]]))),end='')
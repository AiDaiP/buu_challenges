#include <stdio.h>
#include <stdint.h>

int main(int argc, char const *argv[])
{

	uint32_t res[7] = {3746099070,550153460,3774025685,1548802262,2652626477,2230518816};
	for (int i = 0; i <= 4; ++i)
	{
		uint32_t v3 = res[i];
		uint32_t v4 = res[i+1];
		uint32_t v5 = 0x62F35080;//0x458BCD42*64
		for (int j = 0; j <= 0x3f; ++j)
		{
			v4 -= (v3 + v5 + 20) ^ ((v3 << 6) + 3) ^ ((v3 >> 9) + 4) ^ 0x10;
			v3 -= (v4 + v5 + 11) ^ ((v4 << 6) + 2) ^ ((v4 >> 9) + 2) ^ 0x20;
			v5 -= 0x458BCD42;
		}
		printf("%x %x\n",v3,v4);
	}
	return 0;
}


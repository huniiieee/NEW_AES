#include "AES_Enc.h"

int main()
{
	byte Plain[16] = { 0x6a,0x84,0x86,0x7c,0xd7,0x7e,0x12,0xad,0x07,0xea,0x1b,0xe8,0x95,0xc5,0x3f,0xa3 };
	byte Key[16] = { 0, };
	byte Output[16] = { 0, };
	Encryption(Plain, Key, Output);
	for (int i = 0; i < 16; i++)
	{
		printf("%02x ", Output[i]);
	}
	return 0;
}
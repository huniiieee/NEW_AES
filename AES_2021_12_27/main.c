#include "AES_Enc.h"
#include "AES_Dec.h"
#include "Masking.h"
void print_128(byte text[16])
{
	for (int i = 0; i < 16; i++)
	{
		printf("%02x ", text[i]);
	}
	printf("\n");
}

int main()
{
	srand(time(NULL));
	
	for (int i = 0; i < 16; i++)
	{
		Random[i] = rand() & 0xff;
	}

	byte Plain[16] = { 0x6a,0x84,0x86,0x7c,0xd7,0x7e,0x12,0xad,0x07,0xea,0x1b,0xe8,0x95,0xc5,0x3f,0xa3 };
	byte Key[16] = { 0, };
	byte Output[16] = { 0, };
	byte Output1[16] = { 0, };
#if Masking
	printf("PlainText----->");
	print_128(Plain);
	printf("Key      ----->");
	print_128(Key);
	printf("-----------------------------------Encryption-----------------------------------\n");
	printf("CipherText      ----->");
	Masked_Encryption(Plain, Key, Output,Random);
	print_128(Output);
	printf("-----------------------------------Decryption-----------------------------------\n");
	Masked_Decryption(Output, Key, Plain,Random);
	printf("PlainText----->");
	print_128(Plain);
	return 0;
#else
	printf("PlainText----->");
	print_128(Plain);
	printf("Key      ----->");
	print_128(Key);
	printf("-----------------------------------Encryption-----------------------------------\n");
	printf("CipherText      ----->");
	Encryption(Plain, Key, Output);
	print_128(Output);
	printf("-----------------------------------Decryption-----------------------------------\n");
	Decryption(Output, Key, Plain);
	printf("PlainText----->");
	print_128(Plain);
	return 0;
#endif
}
#include "AES_Enc.h"
#include "AES_Dec.h"
#include "Table.h"
#include "Masking.h"

#define Masking 0


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

	Mask AES_mask;
	
	for (int i = 0; i < 16; i++)
	{
		AES_mask.Random[i] = rand() & 0xff;
	}

	AES_mask.S_Input_Mask = rand() & 0xff;
	AES_mask.S_Output_Mask = rand() & 0xff;

	for (int i = 0; i < 256; i++)
	{
		AES_mask.Masked_SBox[i ^ AES_mask.S_Input_Mask] = SBox[i] ^ AES_mask.S_Output_Mask;
	}

	for (int i = 0; i < 4; i++)
		AES_mask.Mixed_Input_Mask[i] = rand() & 0xff;

	byte Mixed_out[16] = { 0, };
	for (int i = 0; i < 16; i++)
	{
		Mixed_out[i] = AES_mask.Mixed_Input_Mask[i / 4];
	}

	MixColumns(Mixed_out);
	for (int i = 0; i < 4; i++)
		AES_mask.Mixed_Output_Mask[i] = Mixed_out[4 * i];

	byte Plain[16] = { 0x6a,0x84,0x86,0x7c,0xd7,0x7e,0x12,0xad,0x07,0xea,0x1b,0xe8,0x95,0xc5,0x3f,0xa3 };
	//byte Plain[16] = { 0, };

	byte Key[16] = { 0, };
	for (int i = 0; i < 16; i++)
	{
		AES_mask.Masked_Key[i] = Key[i] ^ AES_mask.S_Input_Mask;
		AES_mask.Masked_Key[i] = AES_mask.Masked_Key[i] ^ AES_mask.Mixed_Output_Mask[i / 4];
	}

	byte Output[16] = { 0, };
#if Masking

	printf("PlainText----->");
	print_128(Plain);
	for (int i = 0; i < 16; i++)
	{
		Plain[i] = Plain[i] ^ AES_mask.Mixed_Output_Mask[i / 4];
	}
	printf("Key      ----->");
	print_128(Key);
	printf("-----------------------------------Encryption-----------------------------------\n");
	printf("CipherText      ----->");
	Real_Masked_Encryption(Plain, Key, Output, &AES_mask);
	print_128(Output);
	printf("-----------------------------------Decryption-----------------------------------\n");
	//Masked_Decryption(Output, Key, Plain,Random);
	//printf("PlainText----->");
	//print_128(Plain);
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
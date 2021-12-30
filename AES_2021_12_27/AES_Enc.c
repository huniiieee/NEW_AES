#include "AES_Enc.h"
#include "Table.h"


void AddRoundKey(byte Plain[16], byte Key[16])
{
	for (int i = 0; i < 16; i++)
		Plain[i] = Plain[i] ^ Key[i];
}

void SubBytes(byte Plain[16])
{
	for (int i = 0; i < 16; i++)
		Plain[i] = SBox[Plain[i]];
}

void Masked_SubBytes(byte Plain[16],byte Random[16])
{
	for (int i = 0; i < 16; i++)
		Plain[i] = SBox[Plain[i]] ^ Random[i];
}



void ShiftRows(byte Plain[16])
{
	byte T = 0;
	byte T1 = 0;
	byte T2 = 0;

	T = Plain[1];
	Plain[1] = Plain[5];
	Plain[5] = Plain[9];
	Plain[9] = Plain[13];
	Plain[13] = T;

	T = Plain[2];
	T1 = Plain[6];
	Plain[2] = Plain[10];
	Plain[6] = Plain[14];
	Plain[10] = T;
	Plain[14] = T1;

	T = Plain[15];
	Plain[15] = Plain[11];
	Plain[11] = Plain[7];
	Plain[7] = Plain[3];
	Plain[3] = T;
}

byte Xtime_2(byte A)
{
	return (A << 1) ^ ((A >> 7) * 0x1b);
}

void MixColumns(byte Plain[16])
{
	byte Temp[16] = { 0, };
	memcpy(Temp, Plain, 16);
	for (int i = 0; i < 16; i++)
	{
		if (i % 4 == 0)
			Plain[i] = Xtime_2(Temp[i]) ^ Xtime_2(Temp[i + 1]) ^ Temp[i + 1] ^ Temp[i + 2] ^ Temp[i + 3];
		else if (i % 4 == 1)
			Plain[i] = Temp[i - 1] ^ Xtime_2(Temp[i]) ^ Xtime_2(Temp[i + 1]) ^ Temp[i + 1] ^ Temp[i + 2];
		else if (i % 4 == 2)
			Plain[i] = Temp[i - 2] ^ Temp[i - 1] ^ Xtime_2(Temp[i]) ^ Xtime_2(Temp[i + 1]) ^ Temp[i + 1];
		else
			Plain[i] = Xtime_2(Temp[i - 3]) ^ Temp[i - 3] ^ Temp[i - 2] ^ Temp[i - 1] ^ Xtime_2(Temp[i]);
	}
}

void NextKey_Enc(byte Key[16], byte Rcon)
{
	byte Temp[16] = { 0, };
	memcpy(Temp, Key, 16);

	Key[0] = SBox[Temp[13]] ^ Temp[0] ^ Rcon;
	Key[1] = SBox[Temp[14]] ^ Temp[1];
	Key[2] = SBox[Temp[15]] ^ Temp[2];
	Key[3] = SBox[Temp[12]] ^ Temp[3];

	for (int i = 4; i < 16; i++)	
		Key[i] = Key[i - 4] ^ Temp[i];
}

void Encryption(byte Plain[16], byte Key[16], byte Output[16])
{
	AddRoundKey(Plain, Key);
	for (int i = 0; i < 9; i++)
	{
		NextKey_Enc(Key, Rcon[i]);
		SubBytes(Plain);
		ShiftRows(Plain);
		MixColumns(Plain);
		AddRoundKey(Plain, Key);
	}
	NextKey_Enc(Key, Rcon[9]);
	
	SubBytes(Plain);
	ShiftRows(Plain);
	AddRoundKey(Plain, Key);
	memcpy(Output, Plain, 16);
}

void Masked_Encryption(byte Plain[16], byte Key[16], byte Output[16],byte Random[16])
{
	AddRoundKey(Plain, Key);
	for (int i = 0; i < 9; i++)
	{
		NextKey_Enc(Key, Rcon[i]);
		Masked_SubBytes(Plain,Random);
		ShiftRows(Plain);
		MixColumns(Plain);
		AddRoundKey(Plain, Key);
	}
	NextKey_Enc(Key, Rcon[9]);

	Masked_SubBytes(Plain,Random);
	ShiftRows(Plain);
	AddRoundKey(Plain, Key);
	memcpy(Output, Plain, 16);
}
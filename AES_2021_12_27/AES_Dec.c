#include "AES_Dec.h"
#include "Table.h"
#include "AES_Enc.h"


void Inv_SubBytes(byte Cipher[16])
{
	for (int i = 0; i < 16; i++)
		Cipher[i] = Inv_SBox[Cipher[i]];
}

void Masked_Inv_SubBytes(byte Cipher[16], byte Random[16])
{
	for (int i = 0; i < 16; i++)
		Cipher[i] = Inv_SBox[Cipher[i]^Random[i]];
}

void Inv_ShiftRows(byte Cipher[16])
{
	byte T = 0;
	byte T1 = 0;

	T = Cipher[1];
	Cipher[1] = Cipher[13];
	Cipher[13] = Cipher[9];
	Cipher[9] = Cipher[5];
	Cipher[5] = T;

	T = Cipher[2];
	T1 = Cipher[6];
	Cipher[2] = Cipher[10];
	Cipher[6] = Cipher[14];
	Cipher[10] = T;
	Cipher[14] = T1;

	T = Cipher[3];
	Cipher[3] = Cipher[7];
	Cipher[7] = Cipher[11];
	Cipher[11] = Cipher[15];
	Cipher[15] = T;
}

byte Xtime_4(byte A)
{
	return Xtime_2(Xtime_2(A));
}

byte Xtime_8(byte A)
{
	return Xtime_2(Xtime_4(A));
}

byte Xtime_9(byte A)
{
	return Xtime_8(A) ^ A;
}

byte Xtime_b(byte A)
{
	return Xtime_8(A) ^ Xtime_2(A)^A;
}

byte Xtime_d(byte A)
{
	return Xtime_8(A) ^ Xtime_4(A) ^ A;
}

byte Xtime_e(byte A)
{
	return Xtime_8(A) ^ Xtime_4(A) ^ Xtime_2(A);
}

void Inv_MixColumns(byte Cipher[16])
{
	byte Temp[16] = { 0, };
	memcpy(Temp, Cipher, 16);
	for (int i = 0; i < 16; i++)
	{
		if (i % 4 == 0)
			Cipher[i] = Xtime_e(Temp[i]) ^ Xtime_b(Temp[i + 1]) ^ Xtime_d(Temp[i + 2]) ^ Xtime_9(Temp[i + 3]);
		else if (i % 4 == 1)
			Cipher[i] = Xtime_9(Temp[i - 1]) ^ Xtime_e(Temp[i]) ^ Xtime_b(Temp[i + 1]) ^ Xtime_d(Temp[i + 2]);
		else if (i % 4 == 2)
			Cipher[i] = Xtime_d(Temp[i - 2]) ^ Xtime_9(Temp[i - 1]) ^ Xtime_e(Temp[i]) ^ Xtime_b(Temp[i + 1]);
		else
			Cipher[i] = Xtime_b(Temp[i - 3]) ^ Xtime_d(Temp[i - 2]) ^ Xtime_9(Temp[i - 1]) ^ Xtime_e(Temp[i]);
	}
}

void PrevKey_Dec(byte Key[16], byte Rcon)
{
	byte Temp[16] = { 0, };
	memcpy(Temp, Key, 16);

	for (int i = 4; i < 16; i++)
	{
		Key[i] = Temp[i - 4] ^ Key[i];
	}

	Key[0] = SBox[Key[13]] ^ Key[0] ^ Rcon;
	Key[1] = SBox[Key[14]] ^ Key[1];
	Key[2] = SBox[Key[15]] ^ Key[2];
	Key[3] = SBox[Key[12]] ^ Key[3];
}

void Decryption(byte Cipher[16], byte Key[16], byte Output[16])
{
	AddRoundKey(Cipher, Key);

	for (int i = 9; i > 0; i--)
	{
		Inv_ShiftRows(Cipher);
		Inv_SubBytes(Cipher);
		PrevKey_Dec(Key, Rcon[i]);
		AddRoundKey(Cipher, Key);
		Inv_MixColumns(Cipher);
	}
	Inv_ShiftRows(Cipher);
	Inv_SubBytes(Cipher);
	PrevKey_Dec(Key, Rcon[0]);
	AddRoundKey(Cipher, Key);
	memcpy(Output, Cipher, 16);
}

void Masked_Decryption(byte Cipher[16], byte Key[16], byte Output[16], byte Random[16])
{
	AddRoundKey(Cipher, Key);

	for (int i = 9; i > 0; i--)
	{
		Inv_ShiftRows(Cipher);
		Masked_Inv_SubBytes(Cipher,Random);
		PrevKey_Dec(Key, Rcon[i]);
		AddRoundKey(Cipher, Key);
		Inv_MixColumns(Cipher);
	}
	Inv_ShiftRows(Cipher);
	Masked_Inv_SubBytes(Cipher, Random);
	PrevKey_Dec(Key, Rcon[0]);
	AddRoundKey(Cipher, Key);
	memcpy(Output, Cipher, 16);
}
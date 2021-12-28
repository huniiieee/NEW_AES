#ifndef _AES_ENC_H_
#define _AES_ENC_H_

#include "type.h"


void AddRoundKey(byte Plain[16], byte Key[16]);

void SubBytes(byte Plain[16]);

void ShiftRows(byte Plain[16]);

byte Xtime_2(byte A);

void MixColumns(byte Plain[16]);

void NextKey_Enc(byte Key[16], byte Rcon);

void Encryption(byte Plain[16], byte Key[16], byte Output[16]);
#endif

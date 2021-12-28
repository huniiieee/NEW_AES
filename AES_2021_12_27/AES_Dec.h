#ifndef _AES_DEC_H_
#define _AES_DEC_H_

#include "type.h"


void Inv_SubBytes(byte Plain[16]);

void Inv_ShiftRows(byte Plain[16]);

byte Xtime_4(byte A);

byte Xtime_8(byte A);

byte Xtime_9(byte A);

byte Xtime_b(byte A);

byte Xtime_d(byte A);

byte Xtime_e(byte A);

void Inv_MixColumns(byte Plain[16]);

void PrevKey_Dec(byte Key[16], byte Rcon);

void Decryption(byte Plain[16], byte Key[16], byte Output[16]);

#endif
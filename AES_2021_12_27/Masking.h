#ifndef _MASKING_H_
#define _MASKING_H_

#include <stdlib.h>
#include <time.h>
#include "type.h"

typedef struct _Masking_ {
	byte Random[16];
	byte S_Input_Mask;
	byte S_Output_Mask;
	byte Mixed_Input_Mask[4];
	byte Mixed_Output_Mask[4];
	byte Masked_Key[16];
	byte Masked_SBox[256];
	byte Inv_Masked_SBox[256];
} Mask;


#endif
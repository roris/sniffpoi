#ifndef AMF_D_H
#define AMF_D_H
#include "sgint.h"
typedef struct
{
	uint16 l;
	u_char* txt;
} amf_name;
typedef struct
{
	uint8 tid;
	amf_name val;
} amf_str;
#endif

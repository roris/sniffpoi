#ifndef AMF_D_H
#define AMF_D_H

#include <stdint.h>

typedef struct
{
	uint16_t len;
	uint8_t *txt;
} amf_name;

typedef struct
{
	uint8_t type;
	uint16_t len;
	uint8_t *txt;
} amf_str;

typedef struct
{
	uint8_t type;
	uint64_t val;
} amf_num;

typedef struct
{
	uint8_t type;
} amf_nul;
#endif

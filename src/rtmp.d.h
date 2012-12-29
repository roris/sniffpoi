#ifndef RTMP_D_H
#define RTMP_D_H
#include "sgint.h"
/* NOTE: defined for little endian since no one on gikopoi uses big endian cpus.
 */
typedef struct
{
	uint _0:6;
	uint fmt:2;
} hdr_fmt;
typedef struct
{
	uint8 ts_delta[3];
	uint8 len[3];
	uint8 tid;
} msg_type1;
#endif

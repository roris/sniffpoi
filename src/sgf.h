#ifndef SGF_H
#define SGF_H

#include "sgint.h"

volatile struct
{
	uint lctl:2;
	uint comp:2;
	uint wait:4;
} sgf;
#endif

#include "sg.h"

int main(void)
{
	if(sg_init()) return 1;
	sg_sniff();
	return 0;
}
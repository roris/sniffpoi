#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sg_err(const char* fmt, ...)
{
	va_list ap;
	char *buf = malloc(strlen(fmt) + 8);

	strcpy(buf, "ERROR: ");
	strcat(buf, fmt);

	va_start(ap, fmt);
	vfprintf(stderr, buf, ap);
	va_end(ap);

	free(buf);
}

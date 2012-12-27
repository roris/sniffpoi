#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

void sg_err(wchar_t *fmt, ...)
{
	va_list ap;
	wchar_t *buf = malloc((sizeof(wchar_t) * wcslen(fmt))
			      + (sizeof(wchar_t) * 8));
	
	wcscat(buf, L"ERROR:");
	wcscat(buf, fmt);
	wcscat(buf, L"\n");
	
	va_start(ap, fmt);
	vfwprintf(stderr, buf, ap);
	va_end(ap);
	
	free(buf);
}

#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "splog.h"


static FILE *sp_log_file;

void sp_log_status(int level, const char *fmt, ...)
{
	char fmt2[1024] = {0};
	struct tm *tm;
	time_t timeval;
	pid_t pid;
	char timestr[50] = {0};
	va_list ap;

	/* local time or UTC+0000 */
	timeval = time(NULL);

	if (time == -1) {
		goto bad;
	}

	tm = gmtime(timeval);
	if (tm == NULL) {
		goto bad1;
	}

	if (!strftime(timestr, 50, "[%Y-%m-%d][%H:%M:%S] ", &tm)) {
		goto bad2;
	}

	char *lvldesc = level == SPLOG_ERROR ? "!!!ERROR" :
	                level == SPLOG_WARNING ? "!WARNING" : "INFO";

	if (snprintf(fmt2, 1024, "%s:%s: %s", timestr, lvldesc, fmt) < 0) {
		goto bad3;
	}

	va_start(ap, fmt);
	vfprintf(sp_log_file, fmt2, ap);
	va_end(ap);
}



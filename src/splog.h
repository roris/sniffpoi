#pragma once

enum {
	SPLOG_ERROR,
	SPLOG_WARNING,
	SPLOG_INFO
};

void sp_log_status(int level, const char *fmt, ...);
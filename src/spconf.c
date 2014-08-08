#define _POSIX_C_SOURCE 1

#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "spconf.h"
#include "splog.h"

#define DO_NOTHING()    (void)(0)

/*
 * Represents the options that have been loaded.
 */
struct sp_config_read_have_struct {
	int devname	: 1;
	int filter	: 1;
	int bufsize	: 1;
	int timeout	: 1;
	int max_clients	: 1;
	int optimize	: 1;
};

/**
 *
 * @config:	The config structure that is to be filled.
 * @filename:	The name of the config file.
 * @map:	The mapped file object.
 * @curptr:	Pointer to the current character being read.
 * @endptr:	Pointer to the end of the file.
 * @size:	Size of the mapped file.
 * @lineno:	Current line number.
 * @have:	Bit-fields indicating which options have been loaded.
 */
struct sp_config_read_struct {
	struct sp_config *config;

	const char *filename;
	const char *curptr;
	const char *endptr;

	char *map;

	size_t map_size;
	size_t lineno;

	struct sp_config_read_have_struct have;
};

static inline void skip_line(struct sp_config_read_struct *rs)
{
	while (rs->curptr < rs->endptr && *rs->curptr != '\n')
		++rs->curptr;
	++rs->curptr;
}

static inline void skip_spaces(struct sp_config_read_struct *rs)
{
	while (rs->curptr < rs->endptr && isspace(*rs->curptr))
		++rs->curptr;
}

static inline void skip_commented_line(struct sp_config_read_struct *rs)
{
	skip_spaces(rs);

	if (rs->curptr < rs->endptr && '#' == *rs->curptr)
		skip_line(rs);
}

static void check_for_valid_options()
{

}

static void sp_config_parse(struct sp_config_read_struct *rs)
{
	while (rs->curptr < rs->endptr) {

		/* check if we are at a commented line */
		skip_commented_line(rs);

		/* All options start with a character from the alphabet */
		if (!isalpha(* (rs->curptr))) {
			char *fmt = "sp_config_parse: Unexpected '%c' while parsing %s; skipping line %d\n";
			sp_log_status(SPLOG_WARNING, fmt, *rs->curptr, rs->filename, rs->lineno);
			continue;
		}

		check_for_valid_options();
	}
}

static void sp_config_load_defaults(struct sp_config_read_struct *)
{
}

static int sp_config_read_file(FILE *, struct sp_config_read_struct *)
{
	int res;

	return res;
}

static int sp_config_read_map(int fd, struct sp_config_read_struct *rs)
{
	int res;

	rs->map = mmap(NULL, rs->map_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == rs->map) {
		sp_log_status(SPLOG_WARNING, "mmap: %s\n", strerror(errno));
		goto bad;
	}

	rs->curptr = rs->map;
	sp_config_parse(rs);

	/* should the function fail here? */
	if (munmap(rs->map, rs->map_size)) {
		sp_log_status(SPLOG_WARNING, "mmap: %s\n", strerror(errno));
	}

	res = 0;

out:
	return res;

bad:
	res = !0;
	goto out;
}

int sp_config_read(const char *path, struct sp_config *conf)
{
	struct sp_config_read_struct rs;
	int res;
	int fd;
	FILE *fp;
	struct stat sbuf;

	memset(&rs, 0, sizeof(rs));

	fp = fopen(path, "r");

	/* since we don't have a file, we are forced to load the default values */
	if (NULL == fp) {
		sp_log_status(SPLOG_WARNING, "fopen: %s\n", strerror(errno));
		sp_log_status(SPLOG_INFO, "sp_config_read: could not open config file; loading defaults\n", strerror(errno));
		goto load_default;
	}

	fd = fileno(fp);

	if (-1 == fd) {
		sp_log_status(SPLOG_ERROR, "fileno: %s\n", strerror(errno));
		goto bad;
	}

	if (-1 == stat(path, &sbuf)) {
		sp_log_status(SPLOG_ERROR, "fstat: %s\n", strerror(errno));
		goto bad;
	}

	rs.config = conf;
	rs.filename = path;
	rs.map_size = sbuf.st_size;

	if (!sp_config_read_map(fd, &rs) || !sp_config_read_file(fp, &rs))
		DO_NOTHING();

	/* set any value that wasn't loaded to the default */
load_default:
	sp_config_load_defaults(&rs);
	res = 0;
out:
	return res;
bad:
	fclose(fp);
	res = -1;
	goto out;
}

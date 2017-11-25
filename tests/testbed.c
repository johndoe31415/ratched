/**
 *	ratched - TLS connection router that performs a man-in-the-middle attack
 *	Copyright (C) 2017-2017 Johannes Bauer
 *
 *	This file is part of ratched.
 *
 *	ratched is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; this program is ONLY licensed under
 *	version 3 of the License, later versions are explicitly excluded.
 *
 *	ratched is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with ratched; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *	Johannes Bauer <JohannesBauer@gmx.de>
**/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <errno.h>
#include "testbed.h"

static FILE *debug_log = NULL;
static FILE *summary_file = NULL;
static const char *current_testname;
static const char *current_subtestname;
static int failure_count;

bool test_verbose(void) {
	return debug_log != NULL;
}

void debug(const char *msg, ...) {
	if (debug_log != NULL) {
		va_list ap;
		va_start(ap, msg);
		vfprintf(debug_log, msg, ap);
		va_end(ap);
	}
	if (summary_file != NULL) {
		fprintf(summary_file, "# ");
		va_list ap;
		va_start(ap, msg);
		vfprintf(summary_file, msg, ap);
		va_end(ap);
	}
}

void subtest_start_specific(const char *subtestname) {
	if (current_subtestname != NULL) {
		fprintf(stderr, "Tried to start subtest '%s.%s' when still inside subtest '%s.%s'. Aborting.\n", current_testname, current_subtestname, current_testname, subtestname);
		abort();
	}
	current_subtestname = subtestname;
	failure_count = 0;

	fprintf(summary_file, ">> %s %s\n", current_testname, current_subtestname);
	fflush(summary_file);
}

void subtest_finish_specific(const char *subtestname) {
	if (current_subtestname == NULL) {
		fprintf(stderr, "Tried to finish subtest %s without having entered it. Aborting.\n", subtestname);
		abort();
	}
	if (strcmp(subtestname, current_subtestname)) {
		fprintf(stderr, "Tried to finish subtest %s, but currently in subtest %s. Aborting.\n", subtestname, current_subtestname);
		abort();
	}

	debug("Subtest %s: %s.%s\n", (failure_count == 0) ? "PASSED" : "FAILED", current_testname, current_subtestname);
	fprintf(summary_file, "<< %s %s %d\n", current_testname, current_subtestname, failure_count);
	fflush(summary_file);
	current_subtestname = NULL;
}

static void test_syntax(const char *pgmname) {
	fprintf(stderr, "%s (--verbose) (--summary)\n", pgmname);
	fprintf(stderr, "\n");
	fprintf(stderr, "-v, --verbose     Increase verbosity during test.\n");
	fprintf(stderr, "-s, --summary     Only print a test summary, don't do any testing.\n");
}

static void print_headline(const char *text) {
	const int total_length = 80;
	const int dbl_bar_len = total_length - strlen(text);
	const int bar_len = dbl_bar_len / 2;

	for (int i = 0; i < bar_len; i++) {
		fprintf(stderr, "=");
	}
	fprintf(stderr, " %s ", text);
	for (int i = 0; i < dbl_bar_len - bar_len; i++) {
		fprintf(stderr, "=");
	}
	fprintf(stderr, "\n");
}

static int test_print_summary(void) {
	FILE *f = fopen("tests.log", "r");
	if (!f) {
		fprintf(stderr, "Failed to open summary file for reading: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	int conducted_test_cnt = 0;
	int successful_test_cnt = 0;
	int conducted_subtest_cnt = 0;
	int successful_subtest_cnt = 0;
	bool test_successful = false;
	bool subtest_successful = false;
	char line[1024 * 32];

	print_headline("TEST SUMMARY");
	while (fgets(line, sizeof(line) - 1, f)) {
		line[sizeof(line) - 1] = 0;
		int l = strlen(line);
		if (l && (line[0] == '#')) {
			continue;
		}
		if (l && (line[l - 1] == '\r')) {
			line[--l] = 0;
		}
		if (l && (line[l - 1] == '\n')) {
			line[--l] = 0;
		}
		if (!l) {
			continue;
		}

		char *msgtype = strtok(line, " ");
		if (!strcmp(msgtype, ">")) {
			/* Start of test */
			conducted_test_cnt++;
			test_successful = true;
		} else if (!strcmp(msgtype, ">>")) {
			/* Start of subtest */
			conducted_subtest_cnt++;
			subtest_successful = true;
		} else if (!strcmp(msgtype, "<<")) {
			/* End of subtest */
			if (subtest_successful) {
				successful_subtest_cnt++;
			}
		} else if (!strcmp(msgtype, "<")) {
			/* End of test */
			if (test_successful) {
				successful_test_cnt++;
			}
		} else if (!strcmp(msgtype, "-")) {
			/* Failure report */
			test_successful = false;
			subtest_successful = false;
		} else {
			fprintf(stderr, "Do not know how to handle message type '%s'. Aborting.\n", msgtype);
			abort();
		}
	}
	fclose(f);
	const int failed_test_cnt = conducted_test_cnt - successful_test_cnt;
	const int failed_subtest_cnt = conducted_subtest_cnt - successful_subtest_cnt;
	fprintf(stderr, "%d tests: %d PASS, %d FAIL.\n", conducted_test_cnt, successful_test_cnt, failed_test_cnt);
	fprintf(stderr, "%d subtest: %d PASS, %d FAIL.\n", conducted_subtest_cnt, successful_subtest_cnt, failed_subtest_cnt);
	if (failed_test_cnt == 0) {
		print_headline("EVERYTHING OK");
	} else {
		print_headline("FAILED TESTS");
	}

	return (failed_test_cnt > 0) ? 1 : 0;
}

void test_start(int argc, char **argv) {
	const char *new_testname = basename(argv[0]);

	summary_file = fopen("tests.log", "a");
	if (!summary_file) {
		fprintf(stderr, "Failed to open summary file for writing: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct option long_options[] = {
		{"verbose", no_argument, 0, 'v' },
		{"summary", no_argument, 0, 's' },
		{ 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "vs", long_options, NULL)) != -1) {
		switch (opt) {
			case 'v':
				debug_log = stderr;
				break;
			case 's':
				exit(test_print_summary());
				break;
			default:
				fprintf(stderr, "Unexpected option -- %d.\n", opt);
				test_syntax(argv[0]);
				exit(EXIT_FAILURE);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected excess argument.\n");
		test_syntax(argv[0]);
		exit(EXIT_FAILURE);
	}
	current_testname = new_testname;
	fprintf(summary_file, "\n> %s\n", current_testname);
	fflush(summary_file);
}

void test_finished(void) {
	fprintf(summary_file, "\n< %s\n", current_testname);
	fclose(summary_file);
}

void test_fail_ext(const char *file, int line, const char *fncname, const char *reason, failfnc_t failfnc, const void *lhs, const void *rhs) {
	fprintf(summary_file, "- FAILED %s:%d %s: %s.%s (%s)\n", file, line, fncname, current_testname, current_subtestname, reason);
	fprintf(stderr, "FAILED %s:%d %s: %s.%s (%.80s)\n", file, line, fncname, current_testname, current_subtestname, reason);
	if (failfnc != NULL) {
		char *extended_reason = failfnc(lhs, rhs);
		fprintf(summary_file, "- %s\n", extended_reason);
		fprintf(stderr, "   %.120s\n", extended_reason);
		free(extended_reason);
	}
	failure_count++;
}

void test_fail(const char *file, int line, const char *fncname, const char *reason) {
	test_fail_ext(file, line, fncname, reason, NULL, NULL, NULL);
}

char *testbed_failfnc_int(const void *vlhs, const void *vrhs) {
	const int lhs = *((const int*)vlhs);
	const int rhs = *((const int*)vrhs);
	char *result = calloc(1, 64);
	sprintf(result, "LHS = %d, RHS = %d", lhs, rhs);
	return result;
}

char *testbed_failfnc_str(const void *vlhs, const void *vrhs) {
	const char *lhs = (const char*)vlhs;
	const char *rhs = (const char*)vrhs;
	char *result = calloc(1, (lhs ? strlen(lhs) : 5) + (rhs ? strlen(rhs) : 5) + 32);
	char *buf = result;
	if (lhs) {
		buf += sprintf(buf, "LHS = \"%s\"", lhs);
	} else {
		buf += sprintf(buf, "LHS = NULL");
	}
	if (rhs) {
		buf += sprintf(buf, ", RHS = \"%s\"", rhs);
	} else {
		buf += sprintf(buf, ", RHS = NULL");
	}
	return result;
}


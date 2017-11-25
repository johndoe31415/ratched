.PHONY: all test

vpath %.c ..

CFLAGS := -std=c11 -Wall -Werror -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -O3 -I.. -g3 -pthread
CFLAGS += -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=500
ifneq ($(USER),travis)
# On Travis-CI, gcc does not support "undefined" and "leak" sanitizers.
# Furthermore (and worse, actually), there seems to be a kernel < 4.12.8
# installed which causes the address sanitizer to cause spurious fails ("Shadow
# memory range interleaves with an existing memory mapping. ASan cannot proceed
# correctly. ABORTING."), leading to a broken build. Therefore we do not run
# sanitizers on Travis.
CFLAGS += -pie -fPIE -fsanitize=address -fsanitize=undefined -fsanitize=leak
else
# Ignore gcc bug #53119 for travis' old gcc version.
CFLAGS += -Wno-missing-braces
endif
LDFLAGS := -lssl -lcrypto -L/usr/local/lib

TEST_COMMON_OBJS := testbed.o
TEST_OBJS := \
	test_keyvaluelist \
	test_openssl_certs \
	test_openssl_clienthello \
	test_openssl_tls \
	test_parse \
	test_pcapng \
	test_stringlist \
	test_tcpip \
	test_tools

TEST_MANUAL_OBJS := \
	mantest_openssl_sclient \
	mantest_openssl_sserver

all: $(TEST_COMMON_OBJS) $(TEST_OBJS) $(TEST_MANUAL_OBJS)

test_keyvaluelist: $(TEST_COMMON_OBJS) keyvaluelist.o stringlist.o parse.o helper_logging.o
test_openssl_certs: $(TEST_COMMON_OBJS) openssl_certs.o openssl.o helper_logging.o
test_openssl_clienthello: $(TEST_COMMON_OBJS) openssl_clienthello.o openssl.o helper_logging.o
test_openssl_tls: $(TEST_COMMON_OBJS) openssl_tls.o openssl_certs.o openssl.o helper_logging.o ipfwd.o atomic.o thread.o
test_parse: $(TEST_COMMON_OBJS) helper_logging.o parse.o stringlist.o
test_pcapng: $(TEST_COMMON_OBJS) pcapng.o helper_logging.o
test_stringlist: $(TEST_COMMON_OBJS) stringlist.o
test_tcpip: $(TEST_COMMON_OBJS) tcpip.o pcapng.o helper_logging.o
test_tools: $(TEST_COMMON_OBJS) tools.o helper_logging.o

mantest_openssl_sclient: $(TEST_COMMON_OBJS) openssl_tls.o openssl.o helper_logging.o ipfwd.o
mantest_openssl_sserver: $(TEST_COMMON_OBJS) openssl_tls.o openssl_certs.o openssl.o helper_logging.o ipfwd.o

test: all
	rm -f tests.log
	for testname in $(TEST_OBJS); do ./$$testname; done
	@./$(firstword $(TEST_OBJS)) --summary

clean:
	rm -f $(TEST_COMMON_OBJS) $(TEST_OBJS) $(TEST_MANUAL_OBJS) ../*.o *.o
	rm -f tests.log
	rm -f test.pcapng tcpip.pcapng
	rm -f local.key local.crt

.c:
	$(CC) $(CFLAGS) -o $@ $+ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -include testbed.h -c -o $@ $<


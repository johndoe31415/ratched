.PHONY: all clean test tests

OBJS := \
	atomic.o \
	certforgery.o \
	daemonize.o \
	errstack.o \
	hexdump.o \
	interceptdb.o \
	ipfwd.o \
	keyvaluelist.o \
	logging.o \
	ocsp_response.o \
	openssl_certs.o \
	openssl_clienthello.o \
	openssl_fwd.o \
	openssl.o \
	openssl_tls.o \
	parse.o \
	pcapng.o \
	pgmopts.o \
	ratched.o \
	server.o \
	shutdown.o \
	stringlist.o \
	tcpip.o \
	thread.o \
	tools.o

BUILD_TIMESTAMP_UTC := $(shell /bin/date +'%Y-%m-%d %H:%M:%S')
BUILD_REVISION := $(shell git describe --abbrev=10 --dirty --always)

CFLAGS := -O3 -Wall -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=500 -Wno-unused-parameter -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Werror=format -Wshadow -std=c11 -pthread
CFLAGS += -DBUILD_TIMESTAMP_UTC='"$(BUILD_TIMESTAMP_UTC)"' -DBUILD_REVISION='"$(BUILD_REVISION)"'
CFLAGS += -g3
ifneq ($(USER),travis)
# On Travis-CI, gcc does not support "undefined" and "leak" sanitizers.
# Furthermore (and worse, actually), there seems to be a kernel < 4.12.8
# installed which causes the address sanitizer to cause spurious fails ("Shadow
# memory range interleaves with an existing memory mapping. ASan cannot proceed
# correctly. ABORTING."), leading to a broken build. Therefore we do not run
# sanitizers on Travis.
CFLAGS += -pie -fPIE -fsanitize=address -fsanitize=undefined -fsanitize=leak
endif
LDFLAGS := -L/usr/local/lib -lssl -lcrypto

all: ratched

clean:
	rm -f $(OBJS) ratched

ratched: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

test: ratched
	./ratched -o output.pcapng -f 127.0.0.1:5000 -vvv --dump-certs --keyspec ecc:secp256r1 --pcap-comment "foo bar" -i moo,certfile=server/client_moo.crt,keyfile=server/client_moo.key -i koo,clientcert=true --mark-forged-certificates --crl-uri http://foo.com --ocsp-uri http://bar.com

tests:
	make -C tests test

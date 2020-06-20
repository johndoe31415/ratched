.PHONY: all clean test simpletest tests install

OBJS := \
	atomic.o \
	certforgery.o \
	daemonize.o \
	datafilter_bytewise.o \
	datafilter_hexdump.o \
	datafilter_http.o \
	datafilter.o \
	errstack.o \
	hexdump.o \
	hostname_ids.o \
	intercept_config.o \
	interceptdb.o \
	ipfwd.o \
	keyvaluelist.o \
	logging.o \
	map.o \
	ocsp_response.o \
	openssl_certs.o \
	openssl_clienthello.o \
	openssl_filtered_fwd.o \
	openssl.o \
	openssl_tls.o \
	parse.o \
	pcapng.o \
	pgmopts.o \
	ratched.o \
	server.o \
	sighandler.o \
	stringlist.o \
	tcpip.o \
	thread.o \
	tools.o

BUILD_TIMESTAMP_UTC := $(shell /bin/date +'%Y-%m-%d %H:%M:%S')
BUILD_REVISION := $(shell git describe --abbrev=10 --dirty --always)
DEBUG := 0

CFLAGS := -O3 -Wall -Wextra -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=500 -Wno-unused-parameter -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Werror=format -Wshadow -Wmaybe-uninitialized -Wuninitialized -std=c11 -pthread
CFLAGS += -DBUILD_TIMESTAMP_UTC='"$(BUILD_TIMESTAMP_UTC)"' -DBUILD_REVISION='"$(BUILD_REVISION)"'
LDFLAGS := -L/usr/local/lib -lssl -lcrypto

ifeq ($(DEBUG),1)
CFLAGS += -g3

ifneq ($(USER),travis)
# On Travis-CI, gcc does not support "undefined" and "leak" sanitizers.
# Furthermore (and worse, actually), there seems to be a kernel < 4.12.8
# installed which causes the address sanitizer to cause spurious fails ("Shadow
# memory range interleaves with an existing memory mapping. ASan cannot proceed
# correctly. ABORTING."), leading to a broken build. Therefore we do not run
# sanitizers on Travis.
CFLAGS += -pie -fPIE -fsanitize=address -fsanitize=undefined -fsanitize=leak -fno-omit-frame-pointer
endif
endif

all: ratched

clean:
	rm -f $(OBJS) ratched

ratched: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

test: ratched
	ASAN_OPTIONS=fast_unwind_on_malloc=0 ./ratched -o output.pcapng -f 127.0.0.1:9000 -vvv --dump-certs --keyspec ecc:secp256r1 --pcap-comment "foo bar" -i moo,c_certfile=server/client_moo.crt,c_keyfile=server/client_moo.key,s_ciphers=AES128+HIGH+ECDHE -i koo,s_reqclientcert=true --mark-forged-certificates --crl-uri http://foo.com --ocsp-uri http://bar.com --use-ipv6-encapsulation --defaults s_tlsversions=tls10

simpletest: ratched
	./ratched -o output.pcapng -f 127.0.0.1:9000 -vvv --dump-certs

tests:
	make -C tests test

install: all
	strip ratched
	chown root:root ratched
	chmod 755 ratched
	mv ratched /usr/local/bin

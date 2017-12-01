# ratched
[![Build Status](https://travis-ci.org/johndoe31415/ratched.svg?branch=master)](https://travis-ci.org/johndoe31415/ratched)

ratched is a Man-in-the-Middle (MitM) proxy that specifically intercepts TLS
connections. It is intended to be used in conjunction with the Linux iptabes
REDIRECT target; all connections that should be intercepted can be redirected
to the local ratched port. Through the SO_ORIGINAL_DST sockopt, ratched can
determine the intended destination (before iptables packet mangling) and tries
to establish a connection to the original target.

The thing that sets it apart from other MitM software is the following:

  1. ratched does not intercept traffic indiscriminately. In particular, it
	 first waits for the TLS client to send its ClientHello so that ratched can
	 parse it and decide by the Server Name Indication TLS extension (SNI) if
	 the target should be intercepted or not. This is particularly useful when
	 you have virtual hosting, but only want to intercept connections to a
     specific hostname.

  2. ratched is not intended to sniff passwords, but only dumps the traffic
	 into a PCAPNG file. The PCAPNG file format was chosen because it allows
	 for annotation of connections with comments (in particular, which hostname
	 was indicated in the SNI extension) and also allows name resolution
	 information to be embedded in the capture file (again, to map the target
     IP address to the SNI extension's hostname)

# Setup
Once ratched is listening on the routing machine (in the example, on port
9999), simply add an iptables entry that specifies what traffic you want to
capture. For example, to intercept everything from 192.168.1.7 that tries to
reach port 443, use:

```
iptables -t nat -A PREROUTING -p tcp -s 192.168.1.7 --dport 443 -j REDIRECT --to-ports 9999
```

In order to intercept everything that goes to 443, simply do:

```
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 9999
```

# Usage
The help page should be pretty self-explanatory:

[//]: # (Begin of help page -- auto-generated, do not edit!)

```
usage: ratched [-c path] [-f hostname:port] [--single-shot] [--dump-certs]
               [--keyspec keyspec] [--initial-read-timeout secs]
               [--mark-forged-certificates] [--no-recalculate-keyids]
               [--daemonize] [--logfile file] [--flush-logs] [--crl-uri uri]
               [--ocsp-uri uri] [--write-memdumps-into-files]
               [--use-ipv6-encapsulation] [-l hostname:port]
               [-d key=value[,key=value,...]] [-i hostname[,key=value,...]]
               [--pcap-comment comment] [-o filename] [-v]

ratched - TLS connection router that performs a man-in-the-middle attack

optional arguments:
  -c path, --config-dir path
                        Configuration directory where the default root CA
                        certificate, CA keypair and server keypair are stored.
                        Defaults to ~/.config/ratched
  -f hostname:port, --local-fwd hostname:port
                        When local connection to listening port is made, the
                        connection is discarded by default. Specifying this
                        option makes ratched forward to the given
                        hostname/port combination instead. Useful for testing
                        the proxy without the iptables REDIRECT.
  --single-shot         Only handle a single connection and terminate directly
                        after. Useful for debugging purposes.
  --dump-certs          Print created certificates for each intercepted
                        connection in the log file. Note that in many cases
                        you will also need to increase the log level to at
                        least DEBUG in order to see certificates.
  --keyspec keyspec     Specification for the private keys that should be
                        used. Can be either in the form "rsa:bitlen" or
                        "ecc:curvename". Valid choices, therefore, would be,
                        for example, "rsa:1024" or "ecc:secp256r1". Defaults
                        to rsa:2048
  --initial-read-timeout secs
                        Specifies the amount of time in seconds (as a floating
                        point number) that ratched waits for the client to
                        provide its ClientHello before giving up. The default
                        is 1.0 secs.
  --mark-forged-certificates
                        Include an OU=ratched entry to the subjects of all
                        created certificates (including dynamically forged
                        client certificates) for easy debugging.
  --no-recalculate-keyids
                        When forging client certificates, by default the
                        subject and authority key identifiers are removed and
                        recreated to fit the actually used key ids. With this
                        option, they're used as-is (i.e., the key identifier
                        metadata will not fit the actually used keys). This
                        option might expose bugs in certain frameworks which
                        regard these identifiers as trusted information.
  --daemonize           Do not run in foreground mode, but in the background
                        as a daemon.
  --logfile file        Instead of logging to stderr, redirect logs to given
                        file.
  --flush-logs          Flush logfile after each call to logmsg(). Decreases
                        performance, but gives line-buffered logs.
  --crl-uri uri         Encode the given URI into the CRL Distribution Point
                        X.509 extension of server certificates.
  --ocsp-uri uri        Encode the given URI into the Authority Info Access
                        X.509 extension of server certificates as the OCSP
                        responder URI.
  --write-memdumps-into-files
                        When dumping a piece of memory in the log, also output
                        its binary equivalent into a file called
                        hexdump_####.bin, where #### is an ascending number.
                        Useful for debugging of internal data structures.
  --use-ipv6-encapsulation
                        For writing the PCAPNG file format, usually IPv4 is
                        emulated. This has the drawback that when one IPv4
                        endpoint serves multiple servers via the TLS Server
                        Name Indication extension, they cannot be
                        differentiated by their hostname. With this parameter,
                        ratched wraps the packets in IPv4-in-IPv6 emulation
                        and assigns different IPv6 addresses for different
                        server names, thus enabling accurate name resolution.
  -l hostname:port, --listen hostname:port
                        Specify the address and port that ratched is listening
                        on. Defaults to 127.0.0.1:9999.
  -d key=value[,key=value,...], --defaults key=value[,key=value,...]
                        Specify the server and client connection parameters
                        for all hosts that are not explicitly listed via a
                        --intercept option. Arguments are given in a key=value
                        fashion; valid arguments are shown below.
  -i hostname[,key=value,...], --intercept hostname[,key=value,...]
                        Intercept only a specific host name, as indicated by
                        the Server Name Indication inside the ClientHello. Can
                        be specified multiple times to include interception or
                        more than one host. Additional arguments can be
                        specified in a key=value fashion to further define
                        interception parameters for that particular host.
  --pcap-comment comment
                        Store a particular piece of information inside the
                        PCAPNG header as a comment.
  -o filename, --outfile filename
                        Specifies the PCAPNG file that the intercepted traffic
                        is written to. Mandatory argument.
  -v, --verbose         Increase logging verbosity.

The arguments which are valid for the --intercept argument are as follows:
  intercept=[opportunistic|mandatory|forward|reject]
                        Specifies the mode that ratched should act in for
                        this particular connection. Opportunistic TLS
                        interception is the default; it means that TLS
                        interception is tried first. Should it fail, however
                        (because someone tries to send non-TLS traffic), it
                        falls back to 'forward' mode (i.e., forwarding all
                        data unmodified). Mandatory TLS interception means
                        that if no TLS interception is possible, the
                        connection is terminated. 'forward', as explained,
                        simply forwards everything unmodified. 'reject'
                        closes the connection altogether, regardless of the
                        type of seen traffic.
  s_reqclientcert=bool  Ask all connecting clients to the server side of the
                        TLS proxy for a client certificate. If not
                        replacement certificate (at least certfile and
                        keyfile) is given, forge all metadata of the incoming
                        certificate. If a certfile/keyfile is given, this
                        option is implied.
  s_certfile=filename   Specifies an X.509 certificate in PEM format that
                        should be used by ratched as the server certificate.
                        By default, this certificate is automatically
                        generated. Must be used in conjunction with
                        s_keyfile.
  s_keyfile=filename    Specifies the private key for the given server
                        certificate, in PEM format.
  s_chainfile=filename  Specifies the X.509 certificate chain that is to be
                        sent to the client, in PEM format.
  s_cacert=filename     The X.509 CA certificate that issues server
                        certificates, in PEM format.
  s_cakey=filename      The X.509 CA certificate key that signs server
                        certificates, in PEM format.
  s_ciphers=ciphers     The cipher suite string that the ratched TLS server
                        uses.
  s_groups=groups       The key agreement 'supported groups' string (formerly
                        known as 'elliptic curves') that the ratched TLS
                        server uses.
  s_sigalgs=algs        The key agreement 'signature algorithms' string which
                        the ratched TLS server uses.
  c_certfile=filename   Specifies an X.509 certificate in PEM format that
                        should be used by ratched as a client certificate. It
                        will only be used when the connecting client also
                        provided a client certificate. Must be used in
                        conjunction with c_keyfile.
  c_keyfile=filename    The private key for the given client certificate, in
                        PEM format.
  c_chainfile=filename  The X.509 certificate chain that is to be sent to the
                        server, in PEM format.
  c_ciphers=ciphers     The cipher suite string that the ratched TLS client
                        uses.
  c_groups=groups       The key agreement 'supported groups' string (formerly
                        known as 'elliptic curves') that the ratched TLS
                        client uses.
  c_sigalgs=algs        The key agreement 'signature algorithms' string which
                        the ratched TLS client uses.

examples:
    $ ratched -o output.pcapng
      Open up local port 9999 and listen for incoming connections, intercept
      all TLS traffic and write output into given capture file.

    $ ratched -f google.com:443 -o output.pcapng
      Same as before, but redirect all traffic of which the destination cannot
      be determined (e.g., local connections to port 9999) to google.com on
      port 443.

    $ ratched -vvv --dump-certs -o output.pcapng
      Be much more verbose during interception and also print out forged
      certificates in the log.

    $ ratched --defaults intercept=forward -intercept --intercept www.johannes-bauer.com -o output.pcapng
      Do not generally intercept connections (but rather forward all traffic
      unmodified) except for connections with Server Name Indication
      www.johannes-bauer.com, on which interception is performed.

    $ ratched --intercept www.johannes-bauer.com,s_reqclientcert=true -o output.pcapng
      Generally do not request client certificates from connecting peers
      except for connections with Server Name Indication www.johannes-
      bauer.com, where clients are sent a CertificateRequest TLS message. If
      clients do not provide a client certificate, just use regular TLS
      interception. If they do provide a client certificate, forge all client
      certificate metadata and use the forged client certificate in the
      connection against the real server.

    $ ratched --intercept www.johannes-bauer.com,c_certfile=joe.crt,c_keyfile=joe.key -o output.pcapng
      Same as before, but for connections to johannes-bauer.com, do not forge
      client certificates, but always use the given client certificate and key
      (joe.crt / joe.key) for authentication against the server.

    $ ratched --keyspec ecc:secp256r1 --ocsp-uri http://www.ocsp-server.com -o output.pcapng
      Choose secp256r1 instead of RSA-2048 for all used certificates and
      encode an OCSP Responder URI into those forged certificates as well.

    $ ratched --initial-read-timeout 5.0 --default intercept=mandatory -o output.pcapng
      Wait five seconds for connecting clients to send a valid ClientHello
      message. If after five seconds nothing is received or if unknown (non-
      TLS) traffic is received, terminate the connection instead of performing
      unmodified forwarding.
```

[//]: # (End of help page -- auto-generated, do not edit!)

# Naming
The name "ratched" alludes to nurse Ratched of "One Flew Over The Cuckoo's
Nest". If you use the tool to spy on people, you're a complete douchebag and
abusing your power. You should watch the movie. Please use ratched responsibly
to *increase* security of our infrastructure, not undermine it. TLS
interception for spying purposes is despicable and dangerous.

# Dependencies
ratches requires at least OpenSSL v1.1.

# License
ratched is licensed under the GNU GPL-3.

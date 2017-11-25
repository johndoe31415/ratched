# ratched
ratched is a Man-in-the-Middle (MitM) proxy that specifically intercepts TLS
connections. It is intended to be used in conjunction with the Linux iptabes
REDIRECT target; all connections that should be intercepted can be redirected
to the local ratched port. Through the SO_ORIGINAL_DST sockopt, ratched can
determine the intended destination (before iptables packet mangling) and tries
to establish a connection to the original target.

The thing that sets it apart from other MitM software is the following:

  1. ratched does not intercept traffic indiscriminately. In particular, it
	 first waits for the TLS client to send its ClientHello so that ratched can
parse it and decide by the Server Name Indication TLS extension (SNI) if the
target should be intercepted or not. This is particularly useful when you have
virtual hosting, but only want to intercept connections to a specific hostname.

  2. ratched is not intended to sniff passwords, but only dumps the traffic
	 into a PCAPNG file. The PCAPNG file format was chosen because it allows for
     annotation of connections with comments (in particular, which hostname was indicated
     in the SNI extension) and also allows name resolution information to be
     embedded in the capture file (again, to map the target IP address to the SNI
     extension's hostname)

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

```
usage: ratched [-c path] [-f hostname:port] [--single-shot] [--dump-certs]
               [--keyspec keyspec] [--initial-read-timeout secs]
               [--reject-unknown-traffic] [--default-no-intercept]
               [--default-client-cert-request]
               [--default-client-cert certfile:keyfile[:cafile]]
               [--mark-forged-certificates] [--no-recalculate-keyids]
               [--daemonize] [--logfile file] [--flush-logs] [--crl-uri uri]
               [--ocsp-uri uri] [-l hostname:port]
               [-i hostname[,key=value,...]] [--pcap-comment comment]
               [-o filename] [-v]

ratched - TLS connection router that performs a man-in-the-middle attack

optional arguments:
  -c path, --config-dir path
                        Configuration directory where the root CA certificate,
                        CA keypair and server keypair are stored. Defaults to
                        ~/.config/ratched
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
  --reject-unknown-traffic
                        By default, ratched first tries to read a valid
                        ClientHello from the client. If that fails (for
                        example, because the client is not trying to perform a
                        TLS handshake), traffic is routed unmodified. If this
                        option is specified, unrecognized (non-TLS) traffic is
                        not forwarded unmodified, but the connection is closed
                        instead.
  --default-no-intercept
                        The default actions for hosts that have not been
                        explicitly specified is to intercept the connection.
                        This option changes it so that by default, traffic
                        will be routed unmodified unless explicit interception
                        is requested.
  --default-client-cert-request
                        Request by default for clients to provide a client
                        certificate by use of the CertificateRequest TLS
                        message. If a connecting client provides one, it will
                        be replaced either by a forged counterpart (with all
                        the metadata copied from the original) or by the
                        default client certificate (if that option was
                        specified) when connecting to the actual target.
  --default-client-cert certfile:keyfile[:cafile]
                        If a connecting default client sends a client
                        certificate, do not forge the metadata of that
                        certificate to connect to the actual TLS server, but
                        always present this client certificate and key.
                        Optionally can also include a third parameter that
                        specifies the client certificate chain to be sent to
                        the server. All files need to be in PEM format.
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
  -l hostname:port, --listen hostname:port
                        Specify the address and port that ratched is listening
                        on. Defaults to 127.0.0.1:9999.
  -i hostname[,key=value,...], --intercept hostname[,key=value,...]
                        Intercept only a specific host name, as indicated by
                        the Server Name Indication inside the ClientHello. Can
                        be specified multiple times to include interception or
                        more than one host. By default, all targets are
                        intercepted regardless of the hostname. Additional
                        arguments can be specified in a key=value fashion to
                        further define interception parameters for that
                        particular host.
  --pcap-comment comment
                        Store a particular piece of information inside the
                        PCAPNG header as a comment.
  -o filename, --outfile filename
                        Specifies the PCAPNG file that the intercepted traffic
                        is written to. Mandatory argument.
  -v, --verbose         Increase logging verbosity.

The arguments which are valid for the --intercept argument are as follows:
    intercept=bool        Specifies if TLS interception should occur or not.
                          The default value for this option is true.
    clientcert=bool       Ask all connecting clients for a client certificate.
                          If not replacement certificate (at least certfile and
                          keyfile) is given, forge all metadata of the incoming
                          certificate. If a certfile/keyfile is given, this
                          option is implied.
    certfile=filename     Specifies an X.509 certificate in PEM format that
                          should be used by ratched whenever a client tried to
                          send a client certificate. Must be used in
                          conjunction with keyfile.
    keyfile=filename      Specifies the private key for the given certfile in
                          PEM format.
    chainfile=filename    Specifies the X.509 certificate chain that is to be
                          sent to the server, in PEM format.

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

    $ ratched --default-no-intercept --intercept www.johannes-bauer.com -o output.pcapng
      Do not generally intercept connections (but rather forward all traffic
      unmodified) except for connections with Server Name Indication
      www.johannes-bauer.com, on which interception is performed.

    $ ratched --intercept www.johannes-bauer.com,clientcert=true -o output.pcapng
      Generally do not request client certificates from connecting peers
      except for connections with Server Name Indication www.johannes-
      bauer.com, where clients are sent a CertificateRequest TLS message. If
      clients do not provide a client certificate, just use regular TLS
      interception. If they do provide a client certificate, forge all client
      certificate metadata and use the forged client certificate in the
      connection against the real server.

    $ ratched --intercept www.johannes-bauer.com,cerfile=joe.crt,keyfile=joe.key -o output.pcapng
      Same as before, but for connections to johannes-bauer.com, do not forge
      client certificates, but always use the given client certificate and key
      (joe.crt / joe.key) for authentication against the server.

    $ ratched --keyspec ecc:secp256r1 --ocsp-uri http://www.ocsp-server.com -o output.pcapng
      Choose secp256r1 instead of RSA-2048 for all used certificates and
      encode an OCSP Responder URI into those forged certificates as well.

    $ ratched --initial-read-timeout 5.0 --reject-unknown-traffic -o output.pcapng
      Wait five seconds for connecting clients to send a valid ClientHello
      message. If after five seconds nothing is received or if unknown (non-
      TLS) traffic is received, terminate the connection instead of performing
      unmodified forwarding.
```

# Naming
The name "ratched" alludes to Nurse Ratched of "One Flew Over The Cuckoo's
Nest". If you use the tool to spy on people, you're a complete douchebag and
abusing your power. You should watch the movie. Please use ratched responsibly
to *increase* security of our infrastructure, not undermine it. TLS
interception for spying purposes is despicable and dangerous.

# Dependencies
ratches requires at least OpenSSL v1.1.

# License
ratched is licensed under the GNU GPL-3.

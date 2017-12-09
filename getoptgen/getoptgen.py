#!/usr/bin/python3
#	ratched - TLS connection router that performs a man-in-the-middle attack
#	Copyright (C) 2017-2017 Johannes Bauer
#
#	This file is part of ratched.
#
#	ratched is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	ratched is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with ratched; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import os
import textwrap
import argparse
from Patcher import Patcher

parser = argparse.ArgumentParser(prog = "ratched", description = "ratched - TLS connection router that performs a man-in-the-middle attack", add_help = False)
parser.add_argument("-c", "--config-dir", metavar = "path", type = str, help = "Configuration directory where the default root CA certificate, CA keypair and server keypair are stored. Defaults to ~/.config/ratched")
parser.add_argument("-f", "--local-fwd", metavar = "hostname:port", type = str, help = "When local connection to listening port is made, the connection is discarded by default. Specifying this option makes ratched forward to the given hostname/port combination instead. Useful for testing the proxy without the iptables REDIRECT.")
parser.add_argument("--single-shot", action = "store_true", help = "Only handle a single connection and terminate directly after. Useful for debugging purposes.")
parser.add_argument("--dump-certs", action = "store_true", help = "Print created certificates for each intercepted connection in the log file. Note that in many cases you will also need to increase the log level to at least DEBUG in order to see certificates.")
parser.add_argument("--keyspec", metavar = "keyspec", type = str, default = "rsa:2048", help = "Specification for the private keys that should be used. Can be either in the form \"rsa:bitlen\" or \"ecc:curvename\". Valid choices, therefore, would be, for example, \"rsa:1024\" or \"ecc:secp256r1\". Defaults to %(default)s")
parser.add_argument("--initial-read-timeout", metavar = "secs", type = float, default = 1.0, help = "Specifies the amount of time in seconds (as a floating point number) that ratched waits for the client to provide its ClientHello before giving up. The default is %(default).1f secs.")
parser.add_argument("--mark-forged-certificates", action = "store_true", help = "Include an OU=ratched entry to the subjects of all created certificates (including dynamically forged client certificates) for easy debugging.")
parser.add_argument("--no-recalculate-keyids", action = "store_true", help = "When forging client certificates, by default the subject and authority key identifiers are removed and recreated to fit the actually used key ids. With this option, they're used as-is (i.e., the key identifier metadata will not fit the actually used keys). This option might expose bugs in certain frameworks which regard these identifiers as trusted information.")
parser.add_argument("--daemonize", action = "store_true", help = "Do not run in foreground mode, but in the background as a daemon.")
parser.add_argument("--logfile", metavar = "file", help = "Instead of logging to stderr, redirect logs to given file.")
parser.add_argument("--flush-logs", action = "store_true", help = "Flush logfile after each call to logmsg(). Decreases performance, but gives line-buffered logs.")
parser.add_argument("--crl-uri", metavar = "uri", help = "Encode the given URI into the CRL Distribution Point X.509 extension of server certificates.")
parser.add_argument("--ocsp-uri", metavar = "uri", help = "Encode the given URI into the Authority Info Access X.509 extension of server certificates as the OCSP responder URI.")
parser.add_argument("--write-memdumps-into-files", action = "store_true", help = "When dumping a piece of memory in the log, also output its binary equivalent into a file called hexdump_####.bin, where #### is an ascending number. Useful for debugging of internal data structures.")
parser.add_argument("--use-ipv6-encapsulation", action = "store_true", help = "For writing the PCAPNG file format, usually IPv4 is emulated. This has the drawback that when one IPv4 endpoint serves multiple servers via the TLS Server Name Indication extension, they cannot be differentiated by their hostname. With this parameter, ratched wraps the packets in IPv4-in-IPv6 emulation and assigns different IPv6 addresses for different server names, thus enabling accurate name resolution.")
parser.add_argument("-l", "--listen", metavar = "hostname:port", default = "127.0.0.1:9999", help = "Specify the address and port that ratched is listening on. Defaults to %(default)s.")
parser.add_argument("-d", "--defaults", metavar = "key=value[,key=value,...]", type = str, help = "Specify the server and client connection parameters for all hosts that are not explicitly listed via a --intercept option. Arguments are given in a key=value fashion; valid arguments are shown below.")
parser.add_argument("-i", "--intercept", metavar = "hostname[,key=value,...]", help = "Intercept only a specific host name, as indicated by the Server Name Indication inside the ClientHello. Can be specified multiple times to include interception or more than one host. Additional arguments can be specified in a key=value fashion to further define interception parameters for that particular host.")
parser.add_argument("--pcap-comment", metavar = "comment", help = "Store a particular piece of information inside the PCAPNG header as a comment.")
parser.add_argument("-o", "--outfile", metavar = "filename", type = str, help = "Specifies the PCAPNG file that the intercepted traffic is written to. Mandatory argument.")
parser.add_argument("-v", "--verbose", action = "store_true", help = "Increase logging verbosity.")

help_page = parser.format_help()

try:
	os.unlink("spellcheck.txt")
except FileNotFoundError:
	pass
def spellcheck(text):
	with open("spellcheck.txt", "a") as f:
		print(text, file = f)

def format_arg_option(option, description):
	spellcheck(description)
	lines = [ ]
	for line in textwrap.wrap(description, width = 53):
		if len(option) > 20:
			lines.append("  %s" % (option))
			option = ""
		lines.append("  %-20s  %s" % (option, line))
		option = ""
	return "\n".join(lines) + "\n"

def format_example(cmdline, description):
	spellcheck(description)
	lines = [ ]
	lines.append("    %s" % (cmdline))
	lines += textwrap.wrap(description, width = 78, initial_indent = (" " * 6), subsequent_indent = (" " * 6))
	lines.append("")
	return "\n".join(lines) + "\n"

for action in parser._actions:
	spellcheck(action.help)

help_page += """
The arguments which are valid for the --intercept argument are as follows:
"""
help_page += format_arg_option("intercept=[opportunistic|mandatory|forward|reject]", "Specifies the mode that ratched should act in for this particular connection. Opportunistic TLS interception is the default; it means that TLS interception is tried first. Should it fail, however (because someone tries to send non-TLS traffic), it falls back to 'forward' mode (i.e., forwarding all data unmodified). Mandatory TLS interception means that if no TLS interception is possible, the connection is terminated. 'forward', as explained, simply forwards everything unmodified. 'reject' closes the connection altogether, regardless of the type of seen traffic.")
help_page += format_arg_option("s_tlsversions=versions", "Colon-separated string that specifies the acceptable TLS version for the ratched server component. Valid elements are ssl2, ssl3, tls10, tls11, tls12, tls13. Defaults to tls10:tls11:tls12.")
help_page += format_arg_option("s_reqclientcert=bool", "Ask all connecting clients to the server side of the TLS proxy for a client certificate. If not replacement certificate (at least certfile and keyfile) is given, forge all metadata of the incoming certificate. If a certfile/keyfile is given, this option is implied.")
help_page += format_arg_option("s_certfile=filename", "Specifies an X.509 certificate in PEM format that should be used by ratched as the server certificate. By default, this certificate is automatically generated. Must be used in conjunction with s_keyfile.")
help_page += format_arg_option("s_keyfile=filename", "Specifies the private key for the given server certificate, in PEM format.")
help_page += format_arg_option("s_chainfile=filename", "Specifies the X.509 certificate chain that is to be sent to the client, in PEM format.")
help_page += format_arg_option("s_cacert=filename", "The X.509 CA certificate that issues server certificates, in PEM format.")
help_page += format_arg_option("s_cakey=filename", "The X.509 CA certificate key that signs server certificates, in PEM format.")
help_page += format_arg_option("s_ciphers=ciphers", "The cipher suite string that the ratched TLS server uses.")
help_page += format_arg_option("s_groups=groups", "The key agreement 'supported groups' string (formerly known as 'elliptic curves') that the ratched TLS server uses.")
help_page += format_arg_option("s_sigalgs=algs", "The key agreement 'signature algorithms' string which the ratched TLS server uses.")
help_page += format_arg_option("c_tlsversions=versions", "Colon-separated string that specifies the acceptable TLS version for the ratched client component. Valid elements are ssl2, ssl3, tls10, tls11, tls12, tls13. Defaults to tls10:tls11:tls12.")
help_page += format_arg_option("c_certfile=filename", "Specifies an X.509 certificate in PEM format that should be used by ratched as a client certificate. It will only be used when the connecting client also provided a client certificate. Must be used in conjunction with c_keyfile.")
help_page += format_arg_option("c_keyfile=filename", "The private key for the given client certificate, in PEM format.")
help_page += format_arg_option("c_chainfile=filename", "The X.509 certificate chain that is to be sent to the server, in PEM format.")
help_page += format_arg_option("c_ciphers=ciphers", "The cipher suite string that the ratched TLS client uses.")
help_page += format_arg_option("c_groups=groups", "The key agreement 'supported groups' string (formerly known as 'elliptic curves') that the ratched TLS client uses.")
help_page += format_arg_option("c_sigalgs=algs", "The key agreement 'signature algorithms' string which the ratched TLS client uses.")

help_page += """
examples:
"""
help_page += format_example("$ ratched -o output.pcapng", "Open up local port 9999 and listen for incoming connections, intercept all TLS traffic and write output into given capture file.")
help_page += format_example("$ ratched -f google.com:443 -o output.pcapng", "Same as before, but redirect all traffic of which the destination cannot be determined (e.g., local connections to port 9999) to google.com on port 443.")
help_page += format_example("$ ratched -vvv --dump-certs -o output.pcapng", "Be much more verbose during interception and also print out forged certificates in the log.")
help_page += format_example("$ ratched --defaults intercept=forward -intercept --intercept www.johannes-bauer.com -o output.pcapng", "Do not generally intercept connections (but rather forward all traffic unmodified) except for connections with Server Name Indication www.johannes-bauer.com, on which interception is performed.")
help_page += format_example("$ ratched --intercept www.johannes-bauer.com,s_reqclientcert=true -o output.pcapng", "Generally do not request client certificates from connecting peers except for connections with Server Name Indication www.johannes-bauer.com, where clients are sent a CertificateRequest TLS message. If clients do not provide a client certificate, just use regular TLS interception. If they do provide a client certificate, forge all client certificate metadata and use the forged client certificate in the connection against the real server.")
help_page += format_example("$ ratched --intercept www.johannes-bauer.com,c_certfile=joe.crt,c_keyfile=joe.key -o output.pcapng", "Same as before, but for connections to johannes-bauer.com, do not forge client certificates, but always use the given client certificate and key (joe.crt / joe.key) for authentication against the server.")
help_page += format_example("$ ratched --keyspec ecc:secp256r1 --ocsp-uri http://www.ocsp-server.com -o output.pcapng", "Choose secp256r1 instead of RSA-2048 for all used certificates and encode an OCSP Responder URI into those forged certificates as well.")
help_page += format_example("$ ratched --initial-read-timeout 5.0 --default intercept=mandatory -o output.pcapng", "Wait five seconds for connecting clients to send a valid ClientHello message. If after five seconds nothing is received or if unknown (non-TLS) traffic is received, terminate the connection instead of performing unmodified forwarding.")

print(help_page)

markdown_help_page = "\n\n```\n" + help_page.rstrip("\n") + "\n```\n\n"

help_page = help_page.rstrip("\r\n").split("\n")
help_code = ""
for line in help_page:
	line = line.replace("\"", "\\\"")
	help_code += "	fprintf(stderr, \"%s\\n\");\n" % (line)

opts_short = [ ]
opts_long = [ ]
for action in parser._actions:
	requires_parameter = (action.nargs != 0)
	enum_name = "ARG_" + action.dest.upper()

	for option in action.option_strings:
		if option.startswith("--"):
			opts_long.append((option[2:], enum_name, requires_parameter))
		elif (len(option) == 2) and (option[0] == "-"):
			opts_short.append((option[1], enum_name + "_SHORT", requires_parameter))

short_string = ""
for (optchar, enum_name, requires_parameter) in opts_short:
	short_string += optchar
	if requires_parameter:
		short_string += ":"

arg_enum = [ "enum cmdline_arg_t {", "	ARG_ERROR = '?',", "" ]
for (optchar, enum_name, requires_parameter) in opts_short:
	arg_enum.append("	%s = '%s'," % (enum_name, optchar))
arg_enum.append("")
first = True
for (option, enum_name, requires_parameter) in opts_long:
	if first:
		arg_enum.append("	%s = 1000," % (enum_name))
		first = False
	else:
		arg_enum.append("	%s," % (enum_name))
arg_enum.append("};")
arg_enum = "\n".join(arg_enum) + "\n"


cmd_def = [ "	const char *short_options = \"%s\";" % (short_string) ]
cmd_def.append("	struct option long_options[] = {")
for (option, enum_name, requires_parameter) in opts_long:
	param = "\"%s\"," % (option)
	if requires_parameter:
		cmd_def.append("		{ %-30s required_argument, 0, %s }," % (param, enum_name))
	else:
		cmd_def.append("		{ %-30s no_argument,       0, %s }," % (param, enum_name))
cmd_def.append("		{ 0 }")
cmd_def.append("	};")
cmd_def = "\n".join(cmd_def) + "\n"

patcher = Patcher("../pgmopts.c")
patcher.patch("help page", help_code)
patcher.patch("command definition enum", arg_enum)
patcher.patch("command definition", cmd_def)

patcher = Patcher("../README.md", filetype = "markdown")
patcher.patch("help page", markdown_help_page)

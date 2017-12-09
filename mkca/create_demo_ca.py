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
from PKICreator import PKICreator

try:
	os.mkdir("output")
except FileExistsError:
	pass
pki = PKICreator(path_prefix = "output/", default_key = {
	"keytype":	"ecc",
	"curve":	"secp256r1",
})
pki.create_root_ca_cert("root.key", "root.crt", "/CN=Very trustworthy root CA", validity_days = 365 * 5)
pki.create_intermediate_ca_cert("intermediate.key", "intermediate.crt", "root.key", "root.crt", "/CN=Super trustworthy intermediate CA", validity_days = 365 * 5)
pki.create_server_cert("server_foo.key","server_foo.crt", "intermediate.key", "intermediate.crt", "/CN=foo/OU=Server cert", validity_days = 365 * 5, alt_names = [ "foo" ])
pki.create_server_cert("server_bar.key","server_bar.crt", "intermediate.key", "intermediate.crt", "/CN=bar/OU=Server cert", validity_days = 365 * 5, alt_names = [ "bar" ])
pki.create_server_cert("server_moo.key","server_moo.crt", "intermediate.key", "intermediate.crt", "/CN=moo/OU=Server cert", validity_days = 365 * 5, alt_names = [ "moo" ])

pki.create_intermediate_ca_cert("client_intermediate.key", "client_intermediate.crt", "root.key", "root.crt", "/CN=Super trustworthy client intermediate CA", validity_days = 365 * 5)
pki.create_client_cert("client_joe.key","client_joe.crt", "client_intermediate.key", "client_intermediate.crt", "/CN=joe/OU=Client cert", validity_days = 365 * 5)
pki.create_client_cert("client_julaia.key","client_julaia.crt", "client_intermediate.key", "client_intermediate.crt", "/CN=julaia/OU=Client cert", validity_days = 365 * 5)

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
import subprocess
import tempfile

class PKICreator(object):
	_CONFIG_DICT_CA = {
		"basicConstraints":			"critical,CA:TRUE",
		"subjectKeyIdentifier":		"hash",
		"authorityKeyIdentifier":	"keyid,issuer:always",
		"keyUsage":					"digitalSignature,keyEncipherment",
	}

	_CONFIG_DICT_CLIENT_CERT = {
		"nsCertType":				"client",
		"basicConstraints":			"critical,CA:FALSE",
		"subjectKeyIdentifier":		"hash",
		"authorityKeyIdentifier":	"keyid,issuer:always",
		"keyUsage":					"digitalSignature, keyAgreement, keyEncipherment",
		"extendedKeyUsage":			"clientAuth",
	}

	_CONFIG_DICT_SERVER_CERT = {
		"nsCertType":				"server",
		"basicConstraints":			"critical,CA:FALSE",
		"subjectKeyIdentifier":		"hash",
		"authorityKeyIdentifier":	"keyid,issuer:always",
		"keyUsage":					"digitalSignature,keyAgreement,keyEncipherment",
		"extendedKeyUsage":			"serverAuth",
	}

	def __init__(self, path_prefix = "", force = False, default_key = None):
		self._path_prefix = path_prefix
		self._force = force
		self._default_key = default_key

	def _run(self, cmd):
		print()
		print(" ".join(cmd))
		subprocess.check_call(cmd)

	def _fullpath(self, filename):
		return self._path_prefix + filename

	def create_key(self, key_filename, keytype, **args):
		assert(keytype in [ "rsa", "ecc" ])
		if os.path.isfile(self._fullpath(key_filename)) and (not self._force):
			return
		if keytype == "rsa":
			assert("bitlen" in args)
			assert(isinstance(args["bitlen"], int))
			self._run([ "openssl", "genrsa", "-out", self._fullpath(key_filename), str(args["bitlen"]) ])
		elif keytype == "ecc":
			assert("curve" in args)
			self._run([ "openssl", "ecparam", "-name", args["curve"], "-genkey", "-out", self._fullpath(key_filename) ])
		else:
			raise Exception(NotImplemented)

	def _write_openssl_config(self, config_file, config_dict = None, alt_names = None):
		print("[req]", file = config_file)
		print("distinguished_name = localconf", file = config_file)
		print(file = config_file)
		print("[localconf]", file = config_file)
		if config_dict is not None:
			for (key, value) in config_dict.items():
				print("%s = %s" % (key, value), file = config_file)
		if alt_names is not None:
			config_alt_names = [ ]
			for name in alt_names:
				lname = name.lower()
				if not lname.startswith("ip:") and not name.startswith("dns:"):
					# Default to DNS
					name = "DNS:" + name
				config_alt_names.append(name)
			print("subjectAltName = %s" % (",".join(config_alt_names)), file = config_file)
		config_file.flush()

	def create_ss_cert(self, key_filename, cert_filename, subject, validity_days = 365, config_dict = None, alt_names = None):
		if not os.path.isfile(key_filename) and (self._default_key is not None):
			self.create_key(key_filename, **self._default_key)
		if os.path.isfile(self._fullpath(cert_filename)) and (not self._force):
			return

		with tempfile.NamedTemporaryFile("w", suffix = ".conf") as config_file:
			self._write_openssl_config(config_file, config_dict, alt_names)
			self._run([ "openssl", "req", "-new", "-x509", "-key", self._fullpath(key_filename), "-out", self._fullpath(cert_filename), "-subj", subject, "-days", str(validity_days), "-config", config_file.name, "-extensions", "localconf" ])

	def create_cert(self, key_filename, cert_filename, issuer_key_filename, issuer_cert_filename, subject, validity_days = 365, config_dict = None, alt_names = None):
		if not os.path.isfile(self._fullpath(key_filename)) and (self._default_key is not None):
			self.create_key(key_filename, **self._default_key)
		if os.path.isfile(self._fullpath(cert_filename)) and (not self._force):
			return

		with tempfile.NamedTemporaryFile("w", suffix = ".conf") as config_file, tempfile.NamedTemporaryFile("w", suffix = ".csr") as csr_file:
			self._write_openssl_config(config_file, config_dict, alt_names)
			self._run([ "openssl", "req", "-new", "-key", self._fullpath(key_filename), "-out", csr_file.name, "-subj", subject ])
			self._run([ "openssl", "x509", "-req", "-CA", self._fullpath(issuer_cert_filename), "-CAkey", self._fullpath(issuer_key_filename), "-CAcreateserial", "-in", csr_file.name, "-out", self._fullpath(cert_filename), "-days", str(validity_days), "-extfile", config_file.name, "-extensions", "localconf" ])

	def create_root_ca_cert(self, key_filename, cert_filename, subject, validity_days = 365):
		self.create_ss_cert(key_filename, cert_filename, subject, validity_days = validity_days, config_dict = self._CONFIG_DICT_CA)

	def create_intermediate_ca_cert(self, key_filename, cert_filename, issuer_key_filename, issuer_cert_filename, subject, validity_days = 365):
		self.create_cert(key_filename, cert_filename, issuer_key_filename, issuer_cert_filename, subject, validity_days = validity_days, config_dict = self._CONFIG_DICT_CA)

	def create_client_cert(self, key_filename, cert_filename, issuer_key_filename, issuer_cert_filename, subject, validity_days = 365):
		self.create_cert(key_filename, cert_filename, issuer_key_filename, issuer_cert_filename, subject, validity_days = validity_days, config_dict = self._CONFIG_DICT_CLIENT_CERT)

	def create_server_cert(self, key_filename, cert_filename, issuer_key_filename, issuer_cert_filename, subject, alt_names = None, validity_days = 365):
		self.create_cert(key_filename, cert_filename, issuer_key_filename, issuer_cert_filename, subject, validity_days = validity_days, alt_names = alt_names, config_dict = self._CONFIG_DICT_SERVER_CERT)

if __name__ == "__main__":
	pki = PKICreator(force = True)
	pki.create_key("ecc.key", keytype = "ecc", curve = "secp256r1")
	pki.create_key("rsa.key", keytype = "rsa", bitlen = 1024)
	pki.create_key("server.key", keytype = "rsa", bitlen = 1024)
	pki.create_root_ca_cert("ecc.key", "root.crt", "/CN=foobar")
	pki.create_intermediate_ca_cert("rsa.key", "interm.crt", "ecc.key", "root.crt", "/CN=interm")
	pki.create_server_cert("server.key", "server.crt", "rsa.key", "interm.crt", "/CN=server", alt_names = [ "foo.com" ])


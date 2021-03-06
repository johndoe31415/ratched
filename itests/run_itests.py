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

import unittest
import sys
import time
import string
import random
import functools
from SubprocessWrapper import SubprocessWrapper, SubprocessException

def debug_on_error(decoree):
	@functools.wraps(decoree)
	def decorator(self, *args, **kwargs):
		try:
			decoree(self, *args, **kwargs)
			self._recent_test_case_failed = False
		except:
			self._recent_test_case_failed = True
			raise
	return decorator

class RatchedIntegrationTests(unittest.TestCase):
	_UNSCALED_TIMEOUTS = {
		"wait_sserver_ready":			0.2,
		"wait_sclient_ready":			0.2,
		"wait_ratched_ready":			0.2,
		"srv_to_cli_msg":				0.2,
		"cli_to_srv_msg":				0.2,
		"wait_sserver_settle":			0.5,
		"wait_after_sigterm":			0.5,
		"wait_curl_finished":			5,
		"wait_gnutls_finished":			5,
	}
	_TIMEOUTS = { key: value for (key, value) in _UNSCALED_TIMEOUTS.items() }

	def __init__(self, *args, **kwargs):
		unittest.TestCase.__init__(self, *args, **kwargs)
		self._ratched_binary = "../ratched"
		self._test_ca_data_dir = "demo_ca/"
		self._test_ratched_config_dir = "ratched_ca/"
		self._active_processes = [ ]
		self._recent_test_case_failed = False

	@staticmethod
	def _format_cmdline(cmd):
		def escape_arg(arg):
			if any(escchar in arg for escchar in "\"' "):
				# We need to escape
				return "\"%s\"" % (arg.replace("\"", "\\\""))
			else:
				# No escaping needed
				return arg
		return " ".join(escape_arg(arg) for arg in cmd)

	def _start_child(self, cmd, startup_time = None):
		proc = SubprocessWrapper(cmd)
		if startup_time is not None:
			proc.assert_running(startup_time)
		self._active_processes.append(proc)
		return proc

	def setUp(self):
		self._recent_test_case_failed = False

	def tearDown(self):
		if self._recent_test_case_failed:
			print("%d active processes after failed testcase" % (len(self._active_processes)))
			for proc in self._active_processes:
				proc.read(0)
				proc.read_stderr(0)
				proc.dump()
			for proc in self._active_processes:
				print(proc)
			print("~" * 120)
		for proc in self._active_processes:
			proc.shutdown(timeout_before_sigkill_secs = self._TIMEOUTS["wait_after_sigterm"])
		self._active_processes = [ ]

	@staticmethod
	def _get_binnonce(length = 32):
		nonce = [ "+" ] + [ random.choice(string.ascii_lowercase) for i in range(64) ]
		nonce.append("\n")
		return ("".join(nonce)).encode("ascii")

	def _assert_connection_state(self, srv_proc, cli_proc, state):
		nonce1 = self._get_binnonce()
		srv_proc.write(nonce1)
		self.assertIn(nonce1, cli_proc.read_until_data_recvd(timeout_secs = 5.0, expect_data = nonce1))

		nonce2 = self._get_binnonce()
		cli_proc.write(nonce2)
		self.assertIn(nonce2, srv_proc.read_until_data_recvd(timeout_secs = 5.0, expect_data = nonce2))
		return (nonce1, nonce2)

	def _assert_connected(self, srv_proc, cli_proc):
		return self._assert_connection_state(srv_proc, cli_proc, True)

	def _assert_not_connected(self, srv_proc, cli_proc):
		return self._assert_connection_state(srv_proc, cli_proc, False)

	def _start_sserver(self, servername = "bar", require_client = False, webserver = False):
		cmd = [ "openssl", "s_server" ]
		cmd += [ "-cert", self._test_ca_data_dir + "server_%s.crt" % (servername) ]
		cmd += [ "-key", self._test_ca_data_dir + "server_%s.key" % (servername) ]
		cmd += [ "-cert_chain", self._test_ca_data_dir + "intermediate.crt" ]
		cmd += [ "-accept", "10000" ]
		if require_client:
			cmd += [ "-Verify", "5" ]
		if webserver:
			cmd += [ "-www" ]
#		cmd += [ "-debug" ]
		srv = self._start_child(cmd).assert_running(self._TIMEOUTS["wait_sserver_ready"])
		srv.read_until_data_recvd(timeout_secs = 5.0, expect_data = b"ACCEPT\n")
		return srv

	def _start_sclient(self, verify = False, include_trusted_ca = False, include_ratched_ca = False, port = 10000, servername = None, verify_hostname = False, startup_time = None, client_cert = None):
		cmd = [ "openssl", "s_client" ]
		cmd += [ "-connect", "127.0.0.1:%d" % (port) ]
		if verify:
			cmd += [ "-verify", "3", "-verify_return_error" ]
		if include_trusted_ca and include_ratched_ca:
			raise Exception(NotImplemented)
		if include_trusted_ca:
			cmd += [ "-CAfile", self._test_ca_data_dir + "root.crt" ]
		elif include_ratched_ca:
			cmd += [ "-CAfile", self._test_ratched_config_dir + "root.crt" ]
		if servername is not None:
			cmd += [ "-servername", servername ]
			if isinstance(verify_hostname, bool):
				cmd += [ "-verify_hostname", servername ]
			else:
				cmd += [ "-verify_hostname", verify_hostname ]
		if client_cert is not None:
			cmd += [ "-cert", client_cert[0], "-key", client_cert[1] ]
			if len(client_cert) >= 3:
				cmd += [ "-cert_chain", client_cert[2] ]
		cmd += [ "-msg" ]
		cli = self._start_child(cmd).assert_running(self._TIMEOUTS["wait_sclient_ready"])
		cli.read_until_data_recvd(timeout_secs = 5.0, expect_data = b"---\n")
		return cli

	def _start_ratched(self, args = None):
		cmd = [ self._ratched_binary ]
		cmd += [ "-l", "127.0.0.1:10001" ]
		cmd += [ "-f", "127.0.0.1:10000" ]
		cmd += [ "-o", "output.pcapng" ]
		cmd += [ "--config-dir", self._test_ratched_config_dir ]
		if args is not None:
			cmd += args
		ratched = self._start_child(cmd).assert_running(self._TIMEOUTS["wait_ratched_ready"])
		return ratched

	def _start_curl(self, verify = False, port = 10001, trusted_ca = None):
		cmd = [ "curl" ]
		cmd += [ "-vvv" ]
		cmd += [ "--noproxy", "127.0.0.1" ]
		if not verify:
			cmd += [ "--insecure" ]
		if trusted_ca is not None:
			cmd += [ "--cacert", trusted_ca ]
		cmd += [ "https://127.0.0.1:%d" % (port) ]
		curl = self._start_child(cmd)
		curl.wait(self._TIMEOUTS["wait_curl_finished"])
		curl.shutdown(self._TIMEOUTS["wait_curl_finished"])
		return curl

	def _start_gnutls_client(self, verify = False, port = 10001, trusted_ca = None):
		cmd = [ "gnutls-cli" ]
		if not verify:
			cmd += [ "--insecure" ]
		if trusted_ca is not None:
			cmd += [ "--x509cafile=%s" % (trusted_ca) ]
		cmd += [ "--port=%d" % (port), "127.0.0.1" ]
		gnutls = self._start_child(cmd)
		return gnutls

	def _assert_tls_works(self, srv, cli):
		return self._assert_connected(srv, cli)

	def _assert_tls_interception_works(self, srv, cli, ratched, interception_pcapng_filename = "output.pcapng"):
		(nonce1, nonce2) = self._assert_tls_works(srv, cli)
		cli.close_stdin(wait_for_exit_secs = 1.0)
		srv.read_until_data_recvd(timeout_secs = 5.0, expect_data = b"ACCEPT\n")
		ratched.shutdown(timeout_before_sigkill_secs = 5.0)
		with open(interception_pcapng_filename, "rb") as f:
			intercepted_data = f.read()
		self.assertIn(nonce1, intercepted_data)
		self.assertIn(nonce2, intercepted_data)

	@debug_on_error
	def test_server_works_noverify(self):
		srv = self._start_sserver()
		cli = self._start_sclient()
		self._assert_tls_works(srv, cli)

	@debug_on_error
	def test_server_doesnt_work_without_root_ca(self):
		srv = self._start_sserver()
		with self.assertRaises(Exception):
			# Client cannot connect and process will terminate.
			cli = self._start_sclient(verify = True, include_trusted_ca = False)

	@debug_on_error
	def test_server_doesnt_work_with_wrong_hostname(self):
		srv = self._start_sserver()
		with self.assertRaises(Exception):
			# Client cannot connect and process will terminate.
			cli = self._start_sclient(verify = True, include_trusted_ca = True, servername = "xyz", verify_hostname = True)

	@debug_on_error
	def test_server_works_with_root_ca(self):
		srv = self._start_sserver()
		cli = self._start_sclient(verify = True, include_trusted_ca = True, servername = "bar", verify_hostname = True)
		self._assert_tls_works(srv, cli)

	@debug_on_error
	def test_ratched_basic(self):
		srv = self._start_sserver()
		ratched = self._start_ratched()
		cli = self._start_sclient(port = 10001)
		self._assert_tls_interception_works(srv, cli, ratched)

	@debug_on_error
	def test_ratched_odd_hostname(self):
		srv = self._start_sserver()
		ratched = self._start_ratched()
		cli = self._start_sclient(port = 10001, servername = "definitely.some.non.configured.hostname", verify_hostname = True)
		self._assert_tls_interception_works(srv, cli, ratched)

	@debug_on_error
	def test_ratched_disabled_interception(self):
		srv = self._start_sserver()
		ratched = self._start_ratched(args = [ "--defaults", "intercept=forward" ])
		cli = self._start_sclient(port = 10001, verify = True, include_trusted_ca = True, servername = "bar", verify_hostname = True)
		self._assert_tls_works(srv, cli)

	@debug_on_error
	def test_ratched_disabled_interception_except_one(self):
		srv = self._start_sserver()
		ratched = self._start_ratched(args = [ "--defaults", "intercept=forward", "--intercept", "interceptionhost,intercept=mandatory" ])
		cli = self._start_sclient(port = 10001, servername = "interceptionhost", verify_hostname = True)
		self._assert_tls_works(srv, cli)

	@debug_on_error
	def test_ratched_specific_tls_server_config(self):
		srv = self._start_sserver()
		ratched = self._start_ratched(args = [ "--defaults", "s_ciphers=ECDHE-ECDSA-CHACHA20-POLY1305,s_groups=P-256,s_sigalgs=ECDSA+SHA512" ])
		cli = self._start_sclient(port = 10001, servername = "somehost", verify_hostname = True)
		self._assert_tls_works(srv, cli)
		self.assertIn(b"Peer signing digest: SHA512", cli.stdout)
		self.assertIn(b"Server Temp Key: ECDH", cli.stdout)
		self.assertIn(b"Cipher    : ECDHE-ECDSA-CHACHA20-POLY1305", cli.stdout)

	@debug_on_error
	def test_ratched_fails_without_trusted_root(self):
		srv = self._start_sserver()
		ratched = self._start_ratched()
		with self.assertRaises(SubprocessException):
			cli = self._start_sclient(verify = True, port = 10001, servername = "somehost", verify_hostname = True)

	@debug_on_error
	def test_ratched_works_with_trusted_root(self):
		srv = self._start_sserver()
		ratched = self._start_ratched()
		cli = self._start_sclient(verify = True, include_ratched_ca = True, port = 10001, servername = "somehost", verify_hostname = True)
		self._assert_tls_works(srv, cli)

	@debug_on_error
	def test_ratched_odd_hostname_cert(self):
		srv = self._start_sserver()
		ratched = self._start_ratched(args = [ "--intercept", "somehost,s_certfile=%sserver_foo.crt,s_keyfile=%sserver_foo.key,s_chainfile=%sintermediate.crt" % (self._test_ca_data_dir, self._test_ca_data_dir, self._test_ca_data_dir) ])
		cli = self._start_sclient(verify = True, include_trusted_ca = True, port = 10001, servername = "somehost", verify_hostname = "foo")
		self._assert_tls_works(srv, cli)
		self._assert_tls_interception_works(srv, cli, ratched)

	@debug_on_error
	def test_ratched_request_client_cert_non_provided(self):
		srv = self._start_sserver()
		ratched = self._start_ratched(args = [ "--defaults", "s_reqclientcert=true" ])
		cli = self._start_sclient(port = 10001)
		self.assertIn(b"CertificateRequest", cli.stdout)
		self._assert_tls_interception_works(srv, cli, ratched)

	@debug_on_error
	def test_request_client_cert_non_provided_server_needs_one(self):
		srv = self._start_sserver(require_client = True)
		with self.assertRaises(SubprocessException):
			# Client cannot connect, server requires client cert
			cli = self._start_sclient(port = 10000)

	@debug_on_error
	def test_ratched_request_client_cert_non_provided_server_needs_one(self):
		srv = self._start_sserver(require_client = True)
		ratched = self._start_ratched(args = [ "--defaults", "s_reqclientcert=true" ])
		with self.assertRaises(SubprocessException):
			# Client cannot connect, server requires client cert
			cli = self._start_sclient(port = 10001)

	@debug_on_error
	def test_ratched_request_client_cert_used(self):
		srv = self._start_sserver(require_client = True)
		ratched = self._start_ratched(args = [ "--defaults", "s_reqclientcert=true" ])
		cli = self._start_sclient(port = 10001, client_cert = [ "%sclient_joe.crt" % (self._test_ca_data_dir), "%sclient_joe.key" % (self._test_ca_data_dir), "%sclient_intermediate.crt" % (self._test_ca_data_dir) ])
		self._assert_tls_works(srv, cli)

	@debug_on_error
	def test_ratched_request_client_cert_used_specific_cert(self):
		srv = self._start_sserver(require_client = True)
		ratched = self._start_ratched(args = [ "--defaults", "s_reqclientcert=true,c_certfile=%sclient_julaia.crt,c_keyfile=%sclient_julaia.key" % (self._test_ca_data_dir, self._test_ca_data_dir) ])
		cli = self._start_sclient(port = 10001, client_cert = [ "%sclient_joe.crt" % (self._test_ca_data_dir), "%sclient_joe.key" % (self._test_ca_data_dir), "%sclient_intermediate.crt" % (self._test_ca_data_dir) ])
		self._assert_tls_works(srv, cli)
		self.assertIn(b"CN = julaia", srv.stdout)

	@debug_on_error
	def test_sserver_curl(self):
		srv = self._start_sserver(webserver = True)
		cli = self._start_curl(port = 10000)
		self.assertIn(b"Ciphers common between both SSL end points", cli.stdout)

	@debug_on_error
	def test_sserver_curl_requires_cert_fails(self):
		srv = self._start_sserver(webserver = True)
		cli = self._start_curl(port = 10000, verify = True)
		self.assertEqual(cli.status, 60)
		self.assertNotIn(b"Ciphers common between both SSL end points", cli.stdout)

	@debug_on_error
	def test_sserver_curl_requires_cert_works(self):
		srv = self._start_sserver(webserver = True)
		cli = self._start_curl(port = 10000, verify = True, trusted_ca = "%sroot.crt" % (self._test_ca_data_dir))
		self.assertEqual(cli.status, 0)

	@debug_on_error
	def test_ratched_curl(self):
		srv = self._start_sserver(webserver = True)
		ratched = self._start_ratched()
		cli = self._start_curl(port = 10001, verify = True, trusted_ca = "%sroot.crt" % (self._test_ratched_config_dir))
		self.assertEqual(cli.status, 0)
		self.assertIn(b"Ciphers common between both SSL end points", cli.stdout)

	@debug_on_error
	def test_ratched_gnutls_requires_cert(self):
		srv = self._start_sserver()
		ratched = self._start_ratched()
		cli = self._start_gnutls_client(port = 10001, verify = True)
		cli.wait(self._TIMEOUTS["wait_gnutls_finished"])
		cli.shutdown(self._TIMEOUTS["wait_gnutls_finished"])
		self.assertEqual(cli.status, 1)
		self.assertIn(b"The certificate is NOT trusted", cli.stdout)

	@debug_on_error
	def test_ratched_gnutls_requires_cert_works_without_ocsp(self):
		srv = self._start_sserver()
		ratched = self._start_ratched([ "-d", "s_send_rot=true,s_ocsp=false" ])
		cli = self._start_gnutls_client(port = 10001, verify = True, trusted_ca = "%sroot.crt" % (self._test_ratched_config_dir))
		self._assert_tls_interception_works(srv, cli, ratched)

	@debug_on_error
	def test_ratched_gnutls_requires_cert_works_with_ocsp(self):
		srv = self._start_sserver()
		ratched = self._start_ratched([ "-d", "s_send_rot=true" ])
		cli = self._start_gnutls_client(port = 10001, verify = True, trusted_ca = "%sroot.crt" % (self._test_ratched_config_dir))
		self._assert_tls_interception_works(srv, cli, ratched)

if __name__ == "__main__":
	import sys
	suite = unittest.TestSuite()
	tests = RatchedIntegrationTests()

	if len(sys.argv) == 1:
		candidates = sorted(dir(RatchedIntegrationTests))
	else:
		candidates = sys.argv[1:]
	for methodname in candidates:
		if methodname.startswith("test_"):
			suite.addTest(RatchedIntegrationTests(methodname))
	unittest.TextTestRunner().run(suite)


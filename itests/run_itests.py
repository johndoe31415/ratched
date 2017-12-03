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
import time
import string
import random
from SubprocessWrapper import SubprocessWrapper, SubprocessException

class RatchedIntegrationTests(unittest.TestCase):
	_UNSCALED_TIMEOUTS = {
		"wait_sserver_ready":			0.2,
		"wait_sclient_ready":			0.2,
		"wait_ratched_ready":			0.2,
		"srv_to_cli_msg":				0.2,
		"cli_to_srv_msg":				0.2,
		"wait_sserver_settle":			0.5,
		"wait_after_sigterm":			0.5,
	}
	_TIMEOUTS = { key: value for (key, value) in _UNSCALED_TIMEOUTS.items() }

	def __init__(self, *args, **kwargs):
		unittest.TestCase.__init__(self, *args, **kwargs)
		self._ratched_binary = "../ratched"
		self._test_ca_data_dir = "demo_ca/"
		self._active_processes = [ ]

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
		proc = SubprocessWrapper(cmd, startup_time_secs = startup_time)
		self._active_processes.append(proc)
		return proc

	def tearDown(self):
#		for proc in self._active_processes:
#			proc.dump()
#		for proc in self._active_processes:
#			print(proc)
#		print("~" * 120)
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

	def _start_sserver(self, servername = "bar"):
		cmd = [ "openssl", "s_server" ]
		cmd += [ "-cert", self._test_ca_data_dir + "server_%s.crt" % (servername) ]
		cmd += [ "-key", self._test_ca_data_dir + "server_%s.key" % (servername) ]
		cmd += [ "-cert_chain", self._test_ca_data_dir + "intermediate.crt" ]
		cmd += [ "-accept", "10000" ]
#		cmd += [ "-debug" ]
		srv = self._start_child(cmd, startup_time = self._TIMEOUTS["wait_sserver_ready"])
		srv.read_until_data_recvd(timeout_secs = 5.0, expect_data = b"ACCEPT\n")
		return srv

	def _start_sclient(self, verify = False, include_trusted_ca = False, port = 10000, servername = None, verify_hostname = False, startup_time = None):
		cmd = [ "openssl", "s_client" ]
		cmd += [ "-connect", "127.0.0.1:%d" % (port) ]
		if verify:
			cmd += [ "-verify", "3", "-verify_return_error" ]
		if include_trusted_ca:
			cmd += [ "-CAfile", self._test_ca_data_dir + "root.crt" ]
		if servername is not None:
			cmd += [ "-servername", servername ]
			if verify_hostname:
				cmd += [ "-verify_hostname", servername ]
#		cmd += [ "-debug" ]
		cli = self._start_child(cmd, startup_time = self._TIMEOUTS["wait_sclient_ready"])
		cli.read_until_data_recvd(timeout_secs = 5.0, expect_data = b"---\n")
		return cli

	def _start_ratched(self, args = None):
		cmd = [ self._ratched_binary ]
		cmd += [ "-l", "127.0.0.1:10001" ]
		cmd += [ "-f", "127.0.0.1:10000" ]
		cmd += [ "-o", "output.pcapng" ]
		if args is not None:
			cmd += args
		ratched = self._start_child(cmd, startup_time = self._TIMEOUTS["wait_ratched_ready"])
		return ratched

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

	def test_server_works_noverify(self):
		srv = self._start_sserver()
		cli = self._start_sclient()
		self._assert_tls_works(srv, cli)

	def test_server_doesnt_work_without_root_ca(self):
		srv = self._start_sserver()
		with self.assertRaises(Exception):
			# Client cannot connect and process will terminate.
			cli = self._start_sclient(verify = True, include_trusted_ca = False)

	def test_server_doesnt_work_with_wrong_hostname(self):
		srv = self._start_sserver()
		with self.assertRaises(Exception):
			# Client cannot connect and process will terminate.
			cli = self._start_sclient(verify = True, include_trusted_ca = True, servername = "xyz", verify_hostname = True)

	def test_server_works_with_root_ca(self):
		srv = self._start_sserver()
		cli = self._start_sclient(verify = True, include_trusted_ca = True, servername = "bar", verify_hostname = True)
		self._assert_tls_works(srv, cli)

	def test_ratched_basic(self):
		srv = self._start_sserver()
		ratched = self._start_ratched(args = [ "-vvv" ])
		cli = self._start_sclient(port = 10001)
		self._assert_tls_interception_works(srv, cli, ratched)

#	def test_ratched_odd_hostname(self):
#		srv = self._start_sserver()
#		ratched = self._start_ratched()
#		cli = self._start_sclient(port = 10001, servername = "fudisohiuf", verify_hostname = True)
#		self._assert_tls_interception_works(srv, cli)

if __name__ == "__main__":
	unittest.main()

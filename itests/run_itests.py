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
import subprocess
import signal
import time
import fcntl
import select
import os
import string
import random

def set_fd_nonblocking(f):
	fd = f.fileno()
	flags = fcntl.fcntl(fd, fcntl.F_GETFL, 0)
	fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

def read_if_have_data(f, maxlen = None, timeout_secs = 0.1):
	(readable, writable, errored) = select.select([ f.fileno() ], [ ], [ ], timeout_secs)
	if len(readable) > 0:
		return f.read(maxlen)

class RatchedIntegrationTests(unittest.TestCase):
	_UNSCALED_TIMEOUTS = {
		"wait_sserver_ready":			0.1,
		"wait_sclient_ready":			0.1,
		"wait_sserver_startup_msgs":	0.25,
		"wait_sclient_startup_msgs":	0.25,
		"wait_ratched_ready":			0.1,
		"srv_to_cli_msg":				0.1,
		"cli_to_srv_msg":				0.1,
		"wait_sserver_settle":			0.5,
		"wait_after_sigterm":			0.5,
	}
	_TIMEOUTS = { key: 3.0 * value for (key, value) in _UNSCALED_TIMEOUTS.items() }


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
#		print(self._format_cmdline(cmd))
		proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, stdin = subprocess.PIPE)
		set_fd_nonblocking(proc.stdout)
		set_fd_nonblocking(proc.stderr)
		if startup_time is not None:
			try:
				result = proc.wait(timeout = startup_time)

				# Process died!
				proc.stdin.close()
				proc.stdout.close()
				proc.stderr.close()
				raise Exception("Process '%s' died with status %d before initialized after %.1f sec." % (self._format_cmdline(cmd), proc.returncode, startup_time))
			except subprocess.TimeoutExpired:
				# Process still alive after init timeout. All good!
				pass

		self._active_processes.append([ cmd, proc ])
		return proc

	def tearDown(self):
		for (cmd, proc) in self._active_processes:
#			print(self._format_cmdline(cmd))
#			print(proc.stdout.read())
#			print(proc.stderr.read())
#			print()
			proc.stdout.close()
			proc.stderr.close()
			proc.stdin.close()
			proc.send_signal(signal.SIGTERM)
		for (cmd, proc) in self._active_processes:
			try:
				proc.wait(timeout = self._TIMEOUTS["wait_after_sigterm"])
			except subprocess.TimeoutExpired:
				# SIGTERM doesn't work. Alright, the hard way.
				proc.send_signal(signal.SIGKILL)
				proc.wait(timeout = 0.1)
		self._active_processes = [ ]

	@staticmethod
	def _procread(proc, timeout_secs = 0):
		stdout = read_if_have_data(proc.stdout, timeout_secs = timeout_secs)
		stderr = read_if_have_data(proc.stderr, timeout_secs = timeout_secs)
		return (stdout, stderr)

	@staticmethod
	def _get_binnonce(length = 32):
		nonce = [ random.choice(string.ascii_lowercase) for i in range(64) ]
		nonce.append("\n")
		return ("".join(nonce)).encode("ascii")

	def _assert_connection_state(self, srv_proc, cli_proc, state):
		nonce1 = self._get_binnonce()
		srv_proc.stdin.write(nonce1)
		srv_proc.stdin.flush()
		(cli_stdout, cli_stderr) = self._procread(cli_proc, timeout_secs = self._TIMEOUTS["srv_to_cli_msg"])
		self.assertTrue((nonce1 in cli_stdout) == state)

		nonce2 = self._get_binnonce()
		cli_proc.stdin.write(nonce2)
		cli_proc.stdin.flush()
		(srv_stdout, srv_stderr) = self._procread(srv_proc, timeout_secs = self._TIMEOUTS["cli_to_srv_msg"])
		self.assertTrue((nonce2 in srv_stdout) == state)
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
		srv = self._start_child(cmd, startup_time = self._TIMEOUTS["wait_sserver_ready"])
		time.sleep(self._TIMEOUTS["wait_sserver_settle"])
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
		cli = self._start_child(cmd, startup_time = self._TIMEOUTS["wait_sclient_ready"])
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
		(srv_stdout, srv_stderr) = self._procread(srv, timeout_secs = self._TIMEOUTS["wait_sserver_startup_msgs"])
		(cli_stdout, cli_stderr) = self._procread(cli, timeout_secs = self._TIMEOUTS["wait_sclient_startup_msgs"])
		return self._assert_connected(srv, cli)

	def _assert_tls_interception_works(self, srv, cli, interception_pcapng_filename = "output.pcapng"):
		(nonce1, nonce2) = self._assert_tls_works(srv, cli)
		cli.stdin.close()
		time.sleep(0.1)
		with open(interception_pcapng_filename, "rb") as f:
			intercepted_data = f.read()
		self.assertTrue(nonce1 in intercepted_data)
		self.assertTrue(nonce2 in intercepted_data)

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
		ratched = self._start_ratched()
		cli = self._start_sclient(port = 10001)
		self._assert_tls_interception_works(srv, cli)

#	def test_ratched_odd_hostname(self):
#		srv = self._start_sserver()
#		ratched = self._start_ratched()
#		cli = self._start_sclient(port = 10001, servername = "fudisohiuf", verify_hostname = True)
#		self._assert_tls_interception_works(srv, cli)

if __name__ == "__main__":
	unittest.main()

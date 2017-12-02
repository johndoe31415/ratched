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
	def __init__(self, *args, **kwargs):
		unittest.TestCase.__init__(self, *args, **kwargs)
		self._ratched_binary = "../ratched"
		self._test_ca_data_dir = "demo_ca/"
		self._active_processes = [ ]

	def _start_child(self, cmd, startup_time = None):
		proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, stdin = subprocess.PIPE)
		set_fd_nonblocking(proc.stdout)
		set_fd_nonblocking(proc.stderr)
		if startup_time is not None:
			try:
				result = proc.wait(timeout = startup_time)
				# Process died!
				raise Exception("Process '%s' died with status %d before initialized after %.1f sec." % (" ".join(cmd), proc.returncode, startup_time))
			except subprocess.TimeoutExpired:
				# Process still alive after init timeout. All good!
				pass

		self._active_processes.append(proc)
		return proc

	def tearDown(self):
		for proc in self._active_processes:
			proc.stdout.close()
			proc.stderr.close()
			proc.stdin.close()
			proc.send_signal(signal.SIGKILL)
		for proc in self._active_processes:
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
		nonce = self._get_binnonce()
		srv_proc.stdin.write(nonce)
		srv_proc.stdin.flush()
		(cli_stdout, cli_stderr) = self._procread(cli_proc, timeout_secs = 0.1)
		self.assertTrue((nonce in cli_stdout) == state)

		nonce = self._get_binnonce()
		cli_proc.stdin.write(nonce)
		cli_proc.stdin.flush()
		(srv_stdout, srv_stderr) = self._procread(srv_proc, timeout_secs = 0.1)
		self.assertTrue((nonce in srv_stdout) == state)

	def _assert_connected(self, srv_proc, cli_proc):
		self._assert_connection_state(srv_proc, cli_proc, True)

	def _assert_not_connected(self, srv_proc, cli_proc):
		self._assert_connection_state(srv_proc, cli_proc, False)

	def _start_sserver(self, startup_time = 0.1):
		cmd = [ "openssl", "s_server" ]
		cmd += [ "-cert", self._test_ca_data_dir + "server_bar.crt"]
		cmd += [ "-key", self._test_ca_data_dir + "server_bar.key" ]
		cmd += [ "-cert_chain", self._test_ca_data_dir + "intermediate.crt" ]
		cmd += [ "-accept", "10000" ]
		srv = self._start_child(cmd, startup_time = startup_time)
		return srv

	def _start_sclient(self, verify = False, startup_time = None):
		cmd = [ "openssl", "s_client" ]
		cmd += [ "-connect", "127.0.0.1:10000" ]
		if verify:
			cmd += [ "-verify", "3", "-verify_return_error" ]
			cmd += [ "-verifyCAfile", self._test_ca_data_dir + "root.crt" ]
		cli = self._start_child(cmd, startup_time = 0.1)
		return cli

	def test_server_works_noverify(self):
		srv = self._start_sserver()
		cli = self._start_sclient()

		time.sleep(0.1)
		(srv_stdout, srv_stderr) = self._procread(srv)
		(cli_stdout, cli_stderr) = self._procread(cli)
		self._assert_connected(srv, cli)

	def test_server_doesnt_work_without_root_ca(self):
		srv = self._start_sserver()
		with self.assertRaises(Exception):
			# Client cannot connect and process will terminate.
			cli = self._start_sclient(verify = True, startup_time = 0.1)

	def test_server_works_wit_root_ca(self):
		srv = self._start_sserver()
		time.sleep(100)
		cli = self._start_sclient(verify = True)


		time.sleep(0.1)
		(srv_stdout, srv_stderr) = self._procread(srv)
		(cli_stdout, cli_stderr) = self._procread(cli)
		self._assert_connected(srv, cli)


#TestRunner(ratched_binary = "../ratched", test_ca_data_dir = "demo_ca/").run_all()

if __name__ == "__main__":
	unittest.main()

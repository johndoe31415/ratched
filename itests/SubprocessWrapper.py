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
import fcntl
import signal
import subprocess
import select
import time

class SubprocessException(Exception): pass

class SubprocessWrapper(object):
	def __init__(self, cmd, verbose = False):
		self._stdout_data = bytearray()
		self._stderr_data = bytearray()
		self._cmd = cmd
		self._wait_result = None
		self._proc = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, bufsize = 0)
		self._stdin = self._proc.stdin
		self._stdout = self._proc.stdout
		self._stderr = self._proc.stderr
		self._set_fd_nonblocking(self._stdout)
		self._set_fd_nonblocking(self._stderr)

	def assert_running(self, startup_time_secs):
		if not self.expect_process_alive_after(startup_time_secs):
			self.shutdown(0)
			raise SubprocessException("Process %s did not start up properly: Died before %.1f secs were over." % (self, startup_time_secs))
		return self

	@staticmethod
	def _set_fd_nonblocking(f):
		fd = f.fileno()
		flags = fcntl.fcntl(fd, fcntl.F_GETFL, 0)
		fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

	def _read_if_have_data(self, f, maxlen = None, timeout_secs = 0.1):
		(readable, writable, errored) = select.select([ f.fileno() ], [ ], [ ], timeout_secs)
		if len(readable) > 0:
			data = f.read(maxlen)
			return data

	@property
	def proc(self):
		return self._proc

	@property
	def formatted_cmdline(self):
		return self._format_cmdline(self._cmd)

	@property
	def stdout(self):
		return self._stdout_data

	@property
	def stderr(self):
		return self._stderr_data

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

	def wait(self, timeout_secs):
		if self._wait_result is None:
			try:
				self._wait_result = self._proc.wait(timeout = timeout_secs)
			except subprocess.TimeoutExpired:
				# Still alive.
				pass
		return self._wait_result

	def expect_process_alive_after(self, timeout_secs):
		return self.wait(timeout_secs) is None

	def expect_process_terminated_after(self, timeout_secs):
		return self.wait(timeout_secs) is not None

	def shutdown(self, timeout_before_sigkill_secs):
		# Read remaining data
		self.read(0)
		self.read_stderr(0)

		# Then close all FDs
		if self._stdin is not None:
			self._stdin.close()
			self._stdin = None
		if self._stdout is not None:
			self._stdout.close()
			self._stdout = None
		if self._stderr is not None:
			self._stderr.close()
			self._stderr = None

		# And terminate child
		self._proc.send_signal(signal.SIGTERM)
		if not self.expect_process_terminated_after(timeout_before_sigkill_secs):
			print("Sending SIGKILL")
			self._proc.send_signal(signal.SIGKILL)
			if not self.expect_process_terminated_after(1.0):
				raise SubprocessException("Process %s did not terminate even after sending SIGKILL." % (self))

	def close_stdin(self, wait_for_exit_secs = None):
		if self._stdin is not None:
			self._stdin.close()
			self._stdin = None
		if wait_for_exit_secs is not None:
			return self.wait(timeout_secs = wait_for_exit_secs)

	def write(self, data):
		if self._stdin is not None:
			self._stdin.write(data)
			self._stdin.flush()
		else:
			print("ERROR: Cannot write with stdin closed: %s" % (str(data)))

	def _read_from(self, f, timeout_secs, read_until_condition):
		read_data = bytearray()
		if f is None:
			return read_data

		timeout_t = time.time() + timeout_secs
		first = True
		while True:
			remaining_timeout = timeout_t - time.time()
			if (remaining_timeout <= 0) and (not first):
				break
			first = False
			chunk = self._read_if_have_data(f, timeout_secs = max(0, remaining_timeout))
			if (chunk is None) or (len(chunk) == 0):
				break
			read_data += chunk
			if read_until_condition(read_data):
				break
		return read_data

	def read_until_data_recvd(self, timeout_secs, expect_data):
		def condition(read_data):
			return expect_data in read_data
		data = self._read_from(self._stdout, timeout_secs = timeout_secs, read_until_condition = condition)
		self._stdout_data += data
		return data

	def read(self, timeout_secs):
		data = self._read_from(self._stdout, timeout_secs = timeout_secs, read_until_condition = lambda read_data: len(read_data) > 0)
		self._stdout_data += data
		return data

	def read_stderr(self, timeout_secs):
		data = self._read_from(self._stderr, timeout_secs = timeout_secs, read_until_condition = lambda read_data: len(read_data) > 0)
		self._stderr_data += data
		return data

	def dump(self):
		print("Dumping process %s" % (self))
		if len(self._stdout_data) > 0:
			print("<%d bytes stdout>" % (len(self._stdout_data)))
			print(self._stdout_data.decode(errors = "replace"))
		else:
			print("no stdout output")
		print("=" * 120)
		if len(self._stderr_data) > 0:
			print("<%d bytes stderr>" % (len(self._stderr_data)))
			print(self._stderr_data.decode(errors = "replace"))
		else:
			print("no stderr output")
		print("=" * 120)
		print()

	@property
	def status(self):
		return self.wait(0)

	@property
	def status_str(self):
		status = self.status
		if status is None:
			return "still alive"
		else:
			if status < 0:
				try:
					sig = signal.Signals(-status).name
				except ValueError:
					sig = "signal %d" % (-status)
				return "exited %s" % (sig)
			else:
				return "exited %d" % (status)

	def __str__(self):
		return "PID %d (%s): %s" % (self._proc.pid, self.status_str, self.formatted_cmdline)

if __name__ == "__main__":
	proc = SubprocessWrapper([ "sleep", "3" ])
	proc.shutdown(timeout_before_sigkill_secs = 1.0)
	proc.dump()

	proc = SubprocessWrapper([ "cat" ])
	assert(proc.read(timeout_secs = 0.1) is None)
	proc.write(b"foobar")
	assert(proc.read(timeout_secs = 0.1) == b"foobar")
	proc.close_stdin(wait_for_exit_secs = 0.5)
	proc.dump()


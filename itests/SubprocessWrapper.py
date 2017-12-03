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

class SubprocessException(Exception): pass

class SubprocessWrapper(object):
	def __init__(self, cmd, startup_time_secs = None, verbose = False):
		self._stdout_data = bytearray()
		self._stderr_data = bytearray()
		self._cmd = cmd
		self._wait_result = None
		self._proc = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
		self._set_fd_nonblocking(self._proc.stdout)
		self._set_fd_nonblocking(self._proc.stderr)
		if startup_time_secs is not None:
			if not self.expect_process_alive_after(startup_time_secs):
				self.shutdown(0)
				if verbose:
					self.dump()
				raise SubprocessException("Process %s did not start up properly: Died before %.1f secs were over." % (self, startup_time_secs))

	@staticmethod
	def _set_fd_nonblocking(f):
		fd = f.fileno()
		flags = fcntl.fcntl(fd, fcntl.F_GETFL, 0)
		fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

	@staticmethod
	def _read_if_have_data(f, maxlen = None, timeout_secs = 0.1):
		(readable, writable, errored) = select.select([ f.fileno() ], [ ], [ ], timeout_secs)
		if len(readable) > 0:
			return f.read(maxlen)

	@property
	def proc(self):
		return self._proc

	@property
	def formatted_cmdline(self):
		return self._format_cmdline(self._cmd)

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
		self._proc.stdout.close()
		self._proc.stderr.close()
		self._proc.stdin.close()

		# And terminate child
		self._proc.send_signal(signal.SIGTERM)
		if not self.expect_process_terminated_after(timeout_before_sigkill_secs):
			self._proc.send_signal(signal.SIGKILL)
			if not self.expect_process_terminated_after(1.0):
				raise SubprocessException("Process %s did not terminate even after sending SIGKILL." % (self))

	def close_stdin(self, wait_for_exit_secs = None):
		self._proc.stdin.close()
		if wait_for_exit_secs is not None:
			return self.wait(timeout_secs = wait_for_exit_secs)

	def write(self, data):
		self._proc.stdin.write(data)
		self._proc.stdin.flush()

	def _read_from(self, f, data_buf, timeout_secs, read_until_timeout):
		read_data = None
		while True:
			data = self._read_if_have_data(f, timeout_secs = timeout_secs)
			if data is None:
				break
			else:
				if read_data is None:
					read_data = bytearray()
				read_data += data
				if not read_until_timeout:
					break
		if read_data is not None:
			data_buf += read_data
		return read_data

	def read(self, timeout_secs, read_until_timeout = False):
		return self._read_from(self._proc.stdout, self._stdout_data, timeout_secs = timeout_secs, read_until_timeout = read_until_timeout)

	def read_stderr(self, timeout_secs, read_until_timeout = False):
		return self._read_from(self._proc.stderr, self._stderr_data, timeout_secs = timeout_secs, read_until_timeout = read_until_timeout)

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


#!/bin/python2
import crypt
import os
import subprocess
n_pid = os.getpid() + 1
pid = str(n_pid)
val = crypt.crypt(pid, "$1$awesome")
arg = str(val)
cmd = './ch21 ' + arg
subprocess.call(["./ch21", arg])


#!/usr/bin/env python2

import crypt
import os
import subprocess

pid = str(os.getpid()+1)
cpid = str(crypt.crypt(19648, "$1$awesome"))
cmd = './ch21 ' + cpid
print cmd
os.system('./ch21 ' + cpid)

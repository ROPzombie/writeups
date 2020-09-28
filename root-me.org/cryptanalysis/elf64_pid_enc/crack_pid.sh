#!/bin/bash
exec ./ch21 $$

pid=ps | grep ch21
echo "[+] PID: " $pid

#exec ch21 

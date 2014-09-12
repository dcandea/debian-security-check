#!/bin/bash
HOSTNAME=$(hostname);STDOUT=$(/usr/local/bin/dsc.py 2>/dev/null);echo -e $HOSTNAME"\tSecurity Updates\t"$?"\t"$STDOUT"\n"| send_nsca -H NAGIOS_SERVER

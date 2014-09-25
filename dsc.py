#!/usr/bin/env python

"""
dsc.py

Copyright (c) 2007 Adam Hupp <adam nospam hupp.org>
Distributed under the PSF License: http://www.python.org/psf/license/
Nagios check added by dan@quah.ro

This program will detect and warn about unpatched security problems on
a Debian installation.  It does this by looking for any upgradable
packages appear in the security advisories RSS feed.

Requires: python-apt, dctrl-tools, python-feedparser
"""

import sys
import os
import feedparser
import apt
import subprocess
import shlex
import datetime

update_list = []

def source_to_binary(source_package):   
    """Given a source package name, return a list of all installed
    binary packages"""
    
    process = os.popen("grep-status -F Source,Package -s Package -s Status %s |" 
                       "grep-dctrl -F Status --regex installed |"
                      " grep-dctrl -s Package ''" % source_package)
    output = process.readlines()
    # "Package: foo\n" -> "foo"
    return [i.split(None, 1)[1].strip() for i in output]



def src_needs_upgrade(cache, srcpackage):
    """
    Given a source package name and an apt.Cache instance, return True
    if any of its binary packages are upgradable.
    """

    binpackage = source_to_binary(srcpackage)
    status = False

    for i in binpackage:
        if cache[i].is_upgradable:
	    update_list.append(i)
    	    status = True
    return status

if __name__ == "__main__":

    rc = subprocess.call(['apt-get', '-qq', 'update'])
    if rc != 0:
	    print >>sys.stdout, "Something went wrong with apt-get update command!"
	    sys.exit(3)

    cache = apt.Cache()
    feed = feedparser.parse("http://www.debian.org/security/dsa-long")
    if feed.bozo:
        print >>sys.stderr, "Feed exception: ", feed.bozo_exception
        sys.exit(2)

    for i in feed.entries:
        srcpackage = i.title.split()[1]
        if src_needs_upgrade(cache, srcpackage):
            print >>sys.stderr, "Security Update:", srcpackage
            print >>sys.stderr, i.summary.encode('utf-8').strip()
            print >>sys.stderr, ""
            print >>sys.stderr, i.link
            print >>sys.stderr, ""
    if len(update_list) > 0:
	print >>sys.stdout, str(len(update_list)) + " packages needs an update!"
	print >>sys.stderr, "apt-get install",
	runtime = 0
	if os.path.isfile('/tmp/security_check'):
		runtime = os.path.getmtime('/tmp/security_check') - os.path.getatime('/tmp/security_check')
	file = open('/tmp/security_check', 'w')
	for item in update_list:
		print >>sys.stderr, item,
		print >>file, item
	print
	if runtime > 2678400:
		print >>sys.stderr
		print >>sys.stderr, "No security check or system updated for over 30 days. Update system from repository! Execute in shell:"
		print >>sys.stderr
		print >>sys.stderr, 'grep "-security" /etc/apt/sources.list | grep -v "#" > /tmp/security_rep;apt-get upgrade -o Dir::Etc::SourceList=/tmp/security_rep;rm -f /tmp/security_rep'
	sys.exit(2)

process = os.popen("rm -f /tmp/security_check")
print >>sys.stdout, "No security update needed for last 30 days."
sys.exit(0)

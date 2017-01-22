#!/usr/bin/env python

##############################################################################
# Attempting to use python3 instead of 2.7.
#
# Open an OSSEC alert log, parse it, output to csv format.
#

# ######### IMPORTS #########
import os
import sys
import re
import json

# ######### VARIABLES #########
try:
    infile = sys.argv[1]
except:
    print('[-] ERROR: no file provided')
    exit()

ofile = infile + '.csv'

print('[*] reading %s') % infile

# ######### FUNCTIONS #########


# ########## MAIN PROGRAM #########
try:
    ifile = open(infile, 'r')
except IOError:
    print('[-] ERROR: unable to open file.')

ofile = open(ofile, 'w')

'''
The first 3 lines should always be the same...
Alert 1459569598.730897765: - syslog,sshd,invalid_login,authentication_failed,
2016 Apr 01 23:59:58 (dns.sas.upenn.edu) 128.91.234.198->/var/log/secure
Rule: 5710 (level 5) -> 'Attempt to login using a non-existent user'
----
line 1: timestamp:- group array
line 2: date time (hostname) ip_address->/path/to/log/file
line 3: Rule id (level num) -> 'Description'
----
We want the following fields
- timestamp, groups, hostname, rule id, alert level, src ip (if available)
- user (if available), description
Note: when OSSEC client is running on the OSSEC server the hostname is not
      within parens, (). Creating an re for this case, servhostline
'''

# Patterns to match for each line. Use grouping.
alertline = re.compile(r"\*\* Alert (\d+.\d+)*: - (\w+.+)")
hostline = re.compile(r"\d+ \w+ \d+ \d+:\d+:\d+ \((\w+.+)\) (\d+.\d+.\d+.\d+)")
servhostline = re.compile(r"\d+ \w+ \d+ \d+:\d+:\d+ (\w+)")
ruleline = re.compile(r"Rule: (\d+)* \(level (\d+)\) -> '(\w+.+)'")
srcipline = re.compile(r"Src IP: (\d+.\d+.\d+.\d+)")
userline = re.compile(r"User: (\w+)")

# Read each line and display is relative parts
for line in ifile:
    linematched = 0  # TODO: determine if we really need this for anything.
    # Test for matches. A line will have more than one matching RE.
    if alertline.match(line):
        linematched = 1
        match = alertline.match(line)  # we're in the if block, no need to try/except
        ts = match.group(1)
        agroups = match.group(2)  # TODO: this should be an array or a list
        print '[+] timestamp: %s, groups: %s' % (ts, agroups)
        ofile.write('timestamp: ' + ts + ', ' + 'groups: ' + agroups + ', ')

    if hostline.match(line):
        linematched += 1
        match = hostline.match(line)
        host = match.group(1)
        ip = match.group(2)
        print '[*] hostname: %s, ip: %s' % (host, ip)
        ofile.write('host: ' + host + ', ' + 'ip: ' + ip + ', ')

    if servhostline.match(line):
        linematched += 1
        match = servhostline.match(line)
        host = match.group(1)
        ip = '0.0.0.0'
        print '[*] hostname: %s, ip: %s' % (host, ip)
        ofile.write('host: ' + host + ', ' + 'ip: ' + ip + ', ')

    if ruleline.match(line):
        linematched += 1
        match = ruleline.match(line)
        ruleid = match.group(1)
        level = match.group(2)
        desc = match.group(3)
        print '[*] ruleid: %s, level: %s, desc: %s' % (ruleid, level, desc)
        ofile.write('rule_id: ' + ruleid + ', ' + 'level: ' + level + ', ' + 'description: ' + desc + ', ')

    if srcipline.match(line):
        linematched += 1
        match = srcipline.match(line)
        src = match.group(1)
        print '[*] srcip: %s' % src
        ofile.write('src_ip: ' + src + ', ')

    if userline.match(line):
        linematched += 1
        match = userline.match(line)
        user = match.group(1)
        print('[*] user: %s') % user
        ofile.write('user: ' + user + ', ')

    # We need to handle atomic (single log) and composite (multiple logs)
    # rules. Leave logs out to save space.
    if linematched == 0:
        if len(line) > 1:
            # This must be the alert log line
            # (composite alerts have multiple of these)
            print '[*] log: %s' % line
        else:
            # Empty line between alerts
            ofile.write('\n')


ifile.close()
ofile.close()

# Try dumping the data read from ifile to JSON format.
#json.dump(ofile, ifile)


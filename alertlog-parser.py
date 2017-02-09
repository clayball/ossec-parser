#!/usr/bin/env python2

# ############################################################################
# Attempting to use python3 instead of 2.7.
# - ran into issues with 3.. back to 2
#
# OSSEC Alert Log Parser
# ======================
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
try:
    levelmin = sys.argv[2]
except:
    levelmin = 3

tstamp = None
groups = ()
host = None
ip = None
ruleid = None
level = None
desc = None
src = ' '
user = ' '

jsonfile = infile + '.json'
csvfile = infile + '.csv'

print('[*] reading %s') % infile

# ######### FUNCTIONS #########
def initvars ():
    # Initialize variables to None
    tstamp = None
    groups = ()
    host = None
    ip = None
    ruleid = None
    level = None
    desc = None
    src = ' '
    user = ' '


# ########## MAIN PROGRAM #########
try:
    ifile = open(infile, 'r')
except IOError:
    print('[-] ERROR: unable to open file.')

jsonfile = open(jsonfile, 'w')
csvout = open(csvfile, 'w')


'''
The first 3 lines should always be the same...
Alert 1459569598.730897765: - syslog,sshd,invalid_login,authentication_failed,
2016 Apr 01 23:59:58 (dns.sub.host.edu) 10.10.10.10->/var/log/secure
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

# Initialize global variables to None
initvars()

# Read each line and display is relative parts
for line in ifile:
    # TODO: output in JSON format.

    linematched = 0  # TODO: determine if we really need this for anything.
    # Test for matches. A line will have more than one matching RE.
    if alertline.match(line):
        linematched = 1
        #groups = ()
        match = alertline.match(line)  # we're in the if block, no need to try/except
        tstamp = match.group(1)
        groupstr = match.group(2).rstrip(',')  # TODO: make this a list
        #print '[DEBUG] groupstr: %s' % groupstr
        groups = groupstr.split(',')
        #print '[DEBUG] groups: %s, len: %d' % (groups, len(groups))

    if hostline.match(line):  # TODO: doesn't seem to be working
        linematched += 1
        match = hostline.match(line)
        host = match.group(1)
        ip = match.group(2)

    if servhostline.match(line):
        linematched += 1
        match = servhostline.match(line)
        host = match.group(1)
        ip = '0.0.0.0'

    if ruleline.match(line):
        linematched += 1
        match = ruleline.match(line)
        ruleid = match.group(1)
        level = match.group(2)
        desc = match.group(3)

    if srcipline.match(line):
        linematched += 1
        match = srcipline.match(line)
        src = match.group(1)

    if userline.match(line):
        linematched += 1
        match = userline.match(line)
        user = match.group(1)

    # We need to handle atomic (single log) and composite (multiple logs)
    # rules. Leave logs out to save space.
    if linematched == 0:
        if len(line) > 1:
            # This must be the alert log line
            # (composite alerts have multiple of these)
            #print '[*] log: %s' % line
            endalert = 0
        else:
            # Empty line between alerts
            # Only print/write alerts greater than level 7
            #print '[*] LEVEL GREATER THAN 7'
            if int(level) >= int(levelmin):
                print '[alert] %s, %s, %s, %s, %s, %s' % (tstamp, host, ruleid, level, desc, src)

                '''
                alertencoded = json.JSONEncoder().encode({'timestamp': tstamp,
                                           'groups': groups,
                                           'host': host,
                                           'ipv4': ip,
                                           'ruleid': ruleid,
                                           'level': level,
                                           'description': desc,
                                           'source_ip': src,
                                           'user': user
                                           })
                '''

                alertdata = [{'timestamp': tstamp, 'groups': groups,
                                  'host': host, 'ipv4': ip, 'ruleid': ruleid,
                                  'level': level, 'description': desc,
                                  'source_ip': src, 'user': user}]

                json.dump(alertdata, jsonfile, sort_keys=False, indent=4, separators=(',', ': '), encoding="utf-8")

                #print json.dumps({'timestamp': tstamp, 'groups': groups,
                #                  'host': host, 'ipv4': ip, 'ruleid': ruleid,
                #                  'level': level, 'description': desc,
                #                  'source_ip': src, 'user': user
                #                  },
                #                 sort_keys=False, indent=4, separators=(',', ': '), encoding="utf-8")

                # output to csv file, one alert per line (TODO: make this optional)
                csvout.write('tstamp: ' + tstamp + ', groups: ' + groupstr + ', host: ' + host)
                csvout.write(', ip: ' + ip + ', rule_id: ' + ruleid + ', level: ' + level)
                csvout.write(', desc: ' + desc + ', src: ' + src + ', user: ' + user + '\n')
            else:
                print '[*] alert level <= %d: %s' % (int(levelmin), level)
            endalert = 1
            initvars()


ifile.close()
csvout.close()
jsonfile.close()

# Try dumping the data read from ifile to JSON format.
#json.dump(ofile, ifile)


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
from datetime import datetime, date, time
import argparse


# ######### PARSE ARGS #########
# TODO: implement: run on file or directory, min alert level, output csv
# Usage: ./program.py -f file | -d directory [-l 8 --csv]

prog = os.path.basename(sys.argv[0])

filearg = ''
dirarg = ''
csvfile = ''
levelmin = 0
csvarg = ''
c = ''

# Create the argparser object
argparser = argparse.ArgumentParser(description='Process command-line args.'
                                                '  -f or -d is required.')

# Add our arguments
# - either -f or -d is required.
#argparser.add_argument('-f', type=argparse.FileType('r'), help='file to parse', dest='filename')
argparser.add_argument('-f', help='file to parse', dest='filename')
argparser.add_argument('-d', help='directory containing alert logs', dest='directory')
argparser.add_argument('-l', help='minimum alert level', dest='level', type=int, choices=xrange(2, 16))
argparser.add_argument('-o', help='output to CSV format', dest='csvout', choices=['csv'])

args = argparser.parse_args()

if args.level:
    levelmin = args.level
    print '[SET] level %d' % levelmin
else:
    print '[NOT SET] level not provided.'

if args.filename:
    filearg = args.filename
    c = 1
    print '[SET] filename %s' % filearg
else:
    print '[NOT SET] filename not provided.'

if args.directory:
    dirarg = args.directory
    c = 1
    print '[SET] direcory %s' % dirarg

if args.csvout:
    print '[SET] output to CSV'
    # Only do this if -o csv was supplied
    csvfile = filearg + '.csv'

if c != 1:
    argparser.print_help()
    exit()


# ######### VARIABLES #########
datestr = ' '
timestamp = ' '
groups = ()
host = None
ip = None
ruleid = None
level = 1
desc = None
src = ' '
user = ' '

# Name output files same as the input file.
jsonfile = filearg + '.json'

print('[*] reading %s') % filearg

# ######### FUNCTIONS #########
# This usage function is overkill, just all the argparser print_help function
#def usage():
#    # Print usage details
#    print 'print usage'
#    argparser.print_help()

# Initialize variables
def initvars ():
    # Initialize variables to None
    datestr = ''
    timestamp = ''
    groups = ()
    host = None
    ip = None
    ruleid = None
    level = 1
    desc = None
    src = ''
    user = ''


# ########## MAIN PROGRAM #########
#
# hopefully things are good by the time we get here
# TODO: double check the above
infile = open(filearg, 'r')
outjson = open(jsonfile, 'w')
if csvfile:
    print '[debug] open csvfile for writing'


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
dateline = re.compile(r"\d+ \w+ \d+ \d+:\d+:\d+")

# Initialize global variables to None
initvars()

# Read each line and display is relative parts
#for line in str(ifile):
for line in infile:
    linematched = 0  # TODO: determine if we really need this for anything.
    # Test for matches. A line will have more than one matching RE.
    if alertline.match(line):
        linematched = 1
        match = alertline.match(line)
        groupstr = match.group(2).rstrip(',')
        groups = groupstr.split(',')

    if dateline.match(line):
        linematched = 1
        match = dateline.match(line)
        datestr = match.group(0)
        timestamp = datetime.strptime(datestr, "%Y %b %d %H:%M:%S")

    if hostline.match(line):
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
            endalert = 0
        else:
            # Only print/write alerts greater than level set above
            if int(level) >= int(levelmin):
                print '[alert] %s, %s, %s, %s, %s' % \
                      (str(timestamp), host, ruleid, level, src)

                alertdata = [{'timestamp': str(timestamp),
                              'groups': groups, 'host': host, 'ipv4': ip,
                              'ruleid': ruleid, 'level': level,
                              'description': desc, 'source_ip': src,
                              'user': user}]

                json.dump(alertdata, outjson, sort_keys=False, indent=4,
                          separators=(',', ': '), encoding="utf-8")

                # output to csv file, one alert per line
                # (TODO: make this optional)

                #csvout.write('timestamp: ' + str(timestamp) + ', groups: '
                #             + groupstr + ', host: ' + host + ', ip: ' + ip
                #             + ', rule_id: ' + ruleid + ', level: ' + level
                #             + ', desc: ' + desc + ', src: ' + src
                #             + ', user: ' + user + '\n')
            else:
                print '[*] alert level <= %d: %s' % (int(levelmin), level)
            endalert = 1
            initvars()

#csvout.close()
outjson.close()

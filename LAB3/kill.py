import os, sys
import subprocess
import re

ports = ['6583','8471','8681','8683','8685']

if(len(sys.argv)>1):
	ports = sys.argv[1:]

popen = subprocess.Popen(['netstat', '-lpn'],
                         shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
(data, err) = popen.communicate()

pattern = "^tcp.*((?:{0})).* (?P<pid>[0-9]*)/.*$"
pattern = pattern.format(')|(?:'.join(ports))
prog = re.compile(pattern)
for line in data.split('\n'):
    match = re.match(prog, line)
    if match:
        pid = match.group('pid')
        subprocess.Popen(['kill', '-9', pid])
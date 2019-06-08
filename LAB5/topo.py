from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.util import pmonitor

from time import time
from time import sleep
from threading import Thread
from signal import SIGINT
from subprocess import PIPE
import os, errno, sys

TRAFFIC_TIME = 180
ATTACK_TIME = 20
ATTACK_WAIT_TIME = 20

PING_ATTEMPTS = 0
IPERF_TCP_ATTEMPTS = 0
IPERF_UDP_ATTEMPTS = 0

def clean_dumps():
    CURR_DIR = os.getcwd() + '/'
    filenames = ['snort_dump.txt','ping_trafficdump.txt','iperf_udp_trafficdump.txt','iperf_tcp_trafficdump.txt']
    for filename in filenames:
        try:
            os.remove(CURR_DIR+filename)
        except OSError as e:
            if e.errno != errno.ENOENT: # errno.ENOENT = no such file or directory
                raise # re-raise exception if a different error occurred

def parse_ping_dump():
    file = open('ping_trafficdump.txt','r')
    success = 0
    fail = 0
    total = 0
    for line in file.readlines():
        if("packet loss" in line):
            #print line
            if("errors" in line):
                fail = fail + 1
            else:
                success = success + 1
    file.close()
    total = fail+success
    result = {
        "success": success,
        "fail": fail,
        "total": total,
        "attempts": PING_ATTEMPTS,
    }
    print "PING Stats: "+str(result)
    return result

def parse_iperf_udp_dump():
    file = open('iperf_udp_trafficdump.txt','r')
    success = 0
    fail = 0
    total = 0
    for line in file.readlines():
        if("Sending 1470 byte datagrams" in line):
            total = total + 1
        elif("Server Report:" in line):
            success = success + 1
    file.close()
    fail = total - success
    result = {
        "success": success,
        "fail": fail,
        "total": total,
        "attempts": IPERF_UDP_ATTEMPTS,
    }
    print "IPERF UDP Stats: "+str(result)
    return result

def parse_iperf_tcp_dump():
    file = open('iperf_tcp_trafficdump.txt','r')
    success = 0
    fail = 0
    total = 0
    for line in file.readlines():
        if("Client connecting to" in line):
            success = success + 1
    file.close()
    fail = IPERF_TCP_ATTEMPTS - success
    result = {
        "success": success,
        "fail": fail,
        "total": total,
        "attempts": IPERF_TCP_ATTEMPTS,
    }
    print "IPERF TCP Stats: "+str(result)
    return result

def traffic_ping(client,server):
    global PING_ATTEMPTS
    t_end = time() + TRAFFIC_TIME
    while time() < t_end:
        try:
            sleep(3)
            client.cmdPrint('ping', server.IP(),'-c 1 ',' >> ping_trafficdump.txt')
            PING_ATTEMPTS = PING_ATTEMPTS + 1
        except Exception as e:
            print "PING: "+str(e)
    #client.cmdPrint('kill %ping')

# def traffic_wget(client,server):
#     t_end = time() + TRAFFIC_TIME
#     while time() < t_end:
#         try:
#             client.cmdPrint('wget -O - ', server.IP()+":8000",' >> wget_trafficdump.txt')
#             sleep(5)
#         except Exception as e:
#             print str(e)
#     #client.cmdPrint('kill %wget')

def traffic_iperf_udp(client,server):
    global IPERF_UDP_ATTEMPTS
    t_end = time() + TRAFFIC_TIME
    while time() < t_end:
        try:
            #net.iperf((client,server))
            sleep(7)
            client.cmdPrint('iperf -u -c ', server.IP(),' >> iperf_udp_trafficdump.txt')
            IPERF_UDP_ATTEMPTS = IPERF_UDP_ATTEMPTS + 1
        except Exception as e:
            print "UDP: "+str(e)

def traffic_iperf_tcp(client,server):
    global IPERF_TCP_ATTEMPTS
    t_end = time() + TRAFFIC_TIME
    while time() < t_end:
        try:
            #net.iperf((client,server))
            sleep(5)
            client.cmdPrint('iperf -c ', server.IP(),' >> iperf_tcp_trafficdump.txt')
            IPERF_TCP_ATTEMPTS = IPERF_TCP_ATTEMPTS + 1
        except Exception as e:
            print "TCP: "+str(e)

def DOS_SYNFLOOD(client,server):
    sleep(ATTACK_WAIT_TIME)
    print "Starting DOS - SYNFLOOD Attack"
    client.cmdPrint('hping3 -S --flood ', server.IP(),' &')
    #dosPipe = client.popen('hping3 -S --flood ', server.IP())
    sleep(ATTACK_TIME)
    print "Ending DOS - SYNFLOOD Attack"
    procs = client.cmd("ps ax | grep 'hping3 -S --flood "+str(server.IP())+"'")
    procs = procs.split('\n')
    for proc in procs:
        if((('hping3 -S --flood '+str(server.IP())) in proc) and ('grep' not in proc)):
            print proc
            print proc.split(' ')
            pid = proc.split(' ')[0]
            if(len(pid) == 0):
                pid = proc.split(' ')[1]
            pid = int(pid)
            #print "kill "+str(pid)
            client.cmdPrint("kill "+str(pid))
    #dosPipe.send_signal(SIGINT)
    #(output, err) = dosPipe.communicate()
    #dosPipe.terminate()
    print "DOS - SYNFLOOD Attack Finished"
    #print output

def DDOS_SYNFLOOD(client,server):
    sleep(ATTACK_WAIT_TIME)
    print "Starting DDOS - SYNFLOOD Attack"
    client.cmdPrint('hping3 -S --flood --rand-source ', server.IP(),' &')
    #dosPipe = client.popen('hping3 -S --flood ', server.IP())
    sleep(ATTACK_TIME)
    print "Ending DDOS - SYNFLOOD Attack"
    procs = client.cmd("ps ax | grep 'hping3 -S --flood --rand-source "+str(server.IP())+"'")
    procs = procs.split('\n')
    for proc in procs:
        if((('hping3 -S --flood --rand-source '+str(server.IP())) in proc) and ('grep' not in proc)):
            print proc
            print proc.split(' ')
            pid = proc.split(' ')[0]
            if(len(pid) == 0):
                pid = proc.split(' ')[1]
            pid = int(pid)
            #print "kill "+str(pid)
            client.cmdPrint("kill "+str(pid))
    #dosPipe.send_signal(SIGINT)
    #(output, err) = dosPipe.communicate()
    #dosPipe.terminate()
    print "DDOS - SYNFLOOD Attack Finished"

def SPOOF_ATTACK(client,server):
    sleep(ATTACK_WAIT_TIME)
    print "SPOOFING Attack Started"
    t_end = time() + ATTACK_TIME
    while time() < t_end:
        try:
            sleep(3)
            client.cmdPrint('hping3 -d 20 -c 10 -a 172.31.255.3 ', server.IP(),' &')
        except Exception as e:
            print "SPOOF: "+str(e)
    print "SPOOFING Attack Finished"

class MyTopo(Topo):
    def build(self, cnum=4, hnum=1):
        switch = self.addSwitch('s1')

        for h in range(hnum):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)

        for c in range(cnum):
            client = self.addHost('c%s' % (c + 1))
            self.addLink(client, switch)

print "Cleaning dump files"
clean_dumps()

setLogLevel('info')

net = Mininet(topo = MyTopo())
net.start()

print "Dumping host connections"
dumpNodeConnections(net.hosts)

server = net.get('h1')
switch = net.get('s1')
client1, client2, client3, client4 = net.get('c1','c2','c3','c4')

print "Starting Snort on Switch"
switch.cmd("/usr/local/bin/snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i s1-eth1 > snort_dump.txt &")

# print "Starting SimpleHTTPServer on Server"
# server.cmd("python -m SimpleHTTPServer &")

print "Starting iperf Servers on Server"
server.cmd("iperf -s &")
server.cmd("iperf -s -u &")

trafficThreads = []

if(len(sys.argv) > 1):
    ATTACK_TYPE = sys.argv[1].upper()
    TRAFFIC_TIME = int(sys.argv[2])
    ATTACK_TIME = int(sys.argv[3])
    ATTACK_WAIT_TIME = int(sys.argv[4])
else:
    ATTACK_TYPE = raw_input('Attack : DOS or DDOS or SPOOF or NONE? - ').upper()

attackThread = Thread(target=DOS_SYNFLOOD, args=(client4,server), kwargs={})
if(ATTACK_TYPE == 'DDOS'):
    attackThread = Thread(target=DDOS_SYNFLOOD, args=(client4,server), kwargs={})
elif(ATTACK_TYPE == 'SPOOF'):
    attackThread = Thread(target=SPOOF_ATTACK, args=(client4,server), kwargs={})

print "ATTACK_TYPE : "+ATTACK_TYPE.upper()
print "ATTACK_TIME : "+str(ATTACK_TIME)
print "ATTACK_WAIT_TIME : "+str(ATTACK_WAIT_TIME)
print "TRAFFIC_TIME : "+str(TRAFFIC_TIME)

pingThread = Thread(target=traffic_ping, args=(client1,server), kwargs={})
pingThread.start()
trafficThreads.append(pingThread)

# wgetThread = Thread(target=traffic_wget, args=(client2,server), kwargs={})
# wgetThread.start()
# trafficThreads.append(wgetThread)
iperfTCPThread = Thread(target=traffic_iperf_tcp, args=(client2,server), kwargs={})
iperfTCPThread.start()
trafficThreads.append(iperfTCPThread)

iperfUDPThread = Thread(target=traffic_iperf_udp, args=(client3,server), kwargs={})
iperfUDPThread.start()
trafficThreads.append(iperfUDPThread)

if(ATTACK_TYPE != "NONE"):
    attackThread.start()
    trafficThreads.append(attackThread)

# Wait for all threads to complete
for thread in trafficThreads:
    thread.join()

sleep(5)

resultFile = open("results.txt",'a')
resultFile.write("-----------------------------------------\n")
resultFile.write('ATTACK_TYPE : '+str(ATTACK_TYPE)+"\n")
resultFile.write('TRAFFIC_TIME : '+str(TRAFFIC_TIME)+"\n")
resultFile.write('ATTACK_TIME : '+str(ATTACK_TIME)+"\n")
resultFile.write('ATTACK_WAIT_TIME : '+str(ATTACK_WAIT_TIME)+"\n")

pingResults = parse_ping_dump()
tcpResults = parse_iperf_tcp_dump()
udpResults = parse_iperf_udp_dump()

resultFile.write("PING STATS : "+str(pingResults)+"\n")
resultFile.write("TCP STATS : "+str(tcpResults)+"\n")
resultFile.write("UDP STATS : "+str(udpResults)+"\n")
resultFile.close()

#CLI(net)
net.stop()

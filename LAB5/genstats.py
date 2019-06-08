import os

def clean():
	os.system("sudo mn -c")

attacks = ['NONE','DOS','DDOS']

TRAFFIC_TIME = 3*60

ATTACK_TIMES = [20,45,60,75]

ATTACK_WAIT_TIME = 45

for attack in attacks:
	if(attack == 'NONE'):
		clean()
		os.system("sudo python topo.py NONE "+str(TRAFFIC_TIME)+" 0 0")
	else:
		for atktime in ATTACK_TIMES:
			clean()
			os.system("sudo python topo.py "+attack+" "+str(TRAFFIC_TIME)+" "+str(atktime)+" "+str(ATTACK_WAIT_TIME))

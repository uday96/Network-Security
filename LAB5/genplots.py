import numpy as np
import matplotlib.pyplot as plt

def autolabel(rects,ax):
    """
    Attach a text label above each bar displaying its height
    """
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/2., 1.003*height,
                '%d' % int(height),
                ha='center', va='bottom')

def bar_graph(successes,fails,attack,filename,attack_strengths,traffic):
	N = len(successes)
	ind = np.arange(N)  # the x locations for the groups
	width = 0.35       # the width of the bars

	fig, ax = plt.subplots()
	rects1 = ax.bar(ind, successes, width, color='y')
	rects2 = ax.bar(ind + width, fails, width, color='r')

	# add some text for labels, title and axes ticks
	ax.set_ylabel('Attempts')
	ax.set_xlabel('Attack/Traffic Duration (s)')
	ax.set_title('Network '+ traffic+' Stats for '+attack)
	ax.set_xticks(ind + width / 2)
	ax.set_xticklabels(attack_strengths)

	ax.legend((rects1[0], rects2[0]), ('Success', 'Fail'))

	autolabel(rects1,ax)
	autolabel(rects2,ax)

	plt.savefig(filename)
	#plt.show()

def parse_results():
	TRAFFIC_TIME = 3*60
	ATTACK_TIMES = [0,20,45,60,75]
	ATTACK_WAIT_TIME = 45
	results = {
		'ATTACK_TIMES': ATTACK_TIMES,
		'TRAFFIC_TIME': TRAFFIC_TIME,
		'DOS': {
			'ping': {
				'success': [60,29,22,16,18],
				'fail': [0,15,19,22,21]
			},
			'tcp': {
				'success': [12,5,4,3,3],
				'fail': [0,1,7,9,2]
			},
			'udp': {
				'success': [11,4,4,3,2],
				'fail': [0,6,6,7,8]
			}
		},
		'DDOS': {
			'ping': {
				'success': [60,32,26,27,24],
				'fail': [0,15,19,22,21]
			},
			'tcp': {
				'success': [12,4,4,4,3],
				'fail': [0,1,6,7,9]
			},
			'udp': {
				'success': [11,5,3,3,2],
				'fail': [0,5,7,7,8]
			}
		}
	}
	return results

def genplots(results):
	attack_strengths = []
	for t in results['ATTACK_TIMES']:
		attack_strengths.append(str(t)+'/'+str(results['TRAFFIC_TIME']))

	dos = results['DOS']
	ddos = results['DDOS']
	
	for item in dos.items():
		attack = 'DOS'
		if(item[0] == 'ping'):
			traffic = 'PING (ICMP)'
		elif(item[0] == 'tcp'):
			traffic = 'Iperf (TCP)'
		else:
			traffic = 'Iperf (UDP)'
		filename = attack+"_"+item[0]+".png"
		bar_graph(item[1]['success'],item[1]['fail'],attack,filename,attack_strengths,traffic)

	for item in ddos.items():
		attack = 'DDOS'
		if(item[0] == 'ping'):
			traffic = 'PING (ICMP)'
		elif(item[0] == 'tcp'):
			traffic = 'Iperf (TCP)'
		else:
			traffic = 'Iperf (UDP)'
		filename = attack+"_"+item[0]+".png"
		bar_graph(item[1]['success'],item[1]['fail'],attack,filename,attack_strengths,traffic)

results = parse_results()
genplots(results)
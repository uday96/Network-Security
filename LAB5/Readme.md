Files:
	- Makefile : cleans mininet cache and executes topo.py
	- topo.py : Simulate mininet network and attacks
	- genstats.py : Run topo.py for varying attack traffics
	- genplots.py : Generates plots based on results obtained from genstats.py

Execution Command:
	- make
	- python topo.py <attack> <traffictime> <attacktime> <attackwaittime>

- Program Runs Correctly
- No bugs or errors
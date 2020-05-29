# Ping-Implementation-using-Python
Ping is a popular networking application used to test from a remote location whether a particular host is up and reachable. It is also often used to measure latency between the client host and the target host. It works by sending ICMP echo request packets (i.e., ping packets) to the target host and listening for ICMP echo response replies (i.e., pong packets). Ping measures the RRT, records packet loss, and calculates a statistical summary of multiple ping-pong exchanges (the mini- mum, mean, max, and standard deviation of the round-trip times). Write your own Ping application in Python. This program will use ICMP. Follow the official specification in RFC 1739.

Note: Run this code as super-user. On Ubuntu: sudo python3 ping.py

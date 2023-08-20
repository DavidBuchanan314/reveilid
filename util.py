import time

def time_now_micros():
	return int(time.time() * 1_000_000)

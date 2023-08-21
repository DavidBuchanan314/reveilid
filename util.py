import time
import datetime

def time_now_micros() -> int:
	return int(time.time() * 1_000_000)

def epoch_micros_to_human(micros: int) -> str:
	return datetime.datetime.utcfromtimestamp(micros//1_000_000).isoformat()

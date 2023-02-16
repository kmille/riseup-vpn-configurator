import logging
import ping3
ping3.EXCEPTIONS = True


def calc_latency(ip: str) -> float:
    latency = 0.0
    iterations = 4
    for i in range(iterations):
        try:
            lat = ping3.ping(ip, timeout=5)
            latency += lat
        except ping3.errors.PingError as e:
            logging.warning(f"Error ping {ip}: {e}")
    latency_avg = latency / float(iterations)
    return latency_avg

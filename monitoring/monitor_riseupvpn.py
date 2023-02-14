import netifaces
from ping3 import ping
from ping3.errors import PingError

"""
    checks:
    - is there a VPN interface tun0?
    - is the default gateway on tun0?
    - can I ping the gateway of tun0?

    requires:
        sudo pacman -S python-netifaces python-ping3
"""


class Py3status:
    VPN_INTERFACE = "tun0"

    def monitor_host(self):
        state_fail = {'full_text': "VPN: fail",
                      'color': self.py3.COLOR_BAD,
                      'cached_until': self.py3.time_in(seconds=30)
        }
        state_succeed = {'full_text': "VPN: OK",
                         'color': self.py3.COLOR_GOOD,
                         'cached_until': self.py3.time_in(seconds=1*60)
        }

        interfaces = netifaces.interfaces()
        if self.VPN_INTERFACE not in interfaces:
            self.py3.log(f"VPN interface not found ({interfaces})")
            return state_fail

        gw_ip, interface = netifaces.gateways()['default'][netifaces.AF_INET]
        #self.py3.log(gw_ip, interface)
        if interface != self.VPN_INTERFACE:
            self.py3.log(f"Interface of default gateway is not the VPN interface ({interface})")
            return state_fail

        try:
            # ping returns: The delay in seconds/milliseconds, False on error and None on timeout.
            state = ping(gw_ip, timeout=2)
            if not state:
                self.py3.log(f"Ping failed: {state}")
                return state_fail
            return state_succeed
        except PingError:
            return state_fail


if __name__ == "__main__":
    """
    Run module in test mode.
    """
    from py3status.module_test import module_test
    module_test(Py3status)

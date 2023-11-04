import netifaces
from icmplib import ping, ICMPLibError

"""
    checks:
    - is there a VPN interface tun0?
    - is the default gateway on tun0?
    - can I ping the gateway of tun0?

    requires:
        sudo pacman -S python-netifaces python-icmplib
        sudo apt-get install python3-netifaces python3-icmplib
"""


class Py3status:
    VPN_INTERFACE = "tun0"

    def monitor_host(self):
        state_fail = {
            'full_text': "VPN: fail",
            'color': self.py3.COLOR_BAD,
            'cached_until': self.py3.time_in(seconds=10)
        }
        state_succeed = {
            'full_text': "VPN: OK",
            'color': self.py3.COLOR_GOOD,
            'cached_until': self.py3.time_in(seconds=2*60)
        }

        interfaces = netifaces.interfaces()
        if self.VPN_INTERFACE not in interfaces:
            self.py3.log(f"VPN interface does not exist ({interfaces})")
            return state_fail

        gw_ip, interface = netifaces.gateways()['default'][netifaces.AF_INET]
        #self.py3.log(gw_ip, interface)
        if interface != self.VPN_INTERFACE:
            self.py3.log(f"Default gateway interface is not the VPN interface ({interface})")
            return state_fail

        try:
            resp = ping(gw_ip, timeout=2,
                        count=1, privileged=False)
            #self.py3.log(resp)
            return state_succeed
        except ICMPLibError as e:
            self.py3.log(f"Ping failed: {e}")
            return state_fail


if __name__ == "__main__":
    """
    Run module in test mode.
    """
    from py3status.module_test import module_test
    module_test(Py3status)

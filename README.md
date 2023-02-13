# riseup-vpn-configurator

> Riseup offers Personal VPN service for censorship circumvention, location anonymization and traffic encryption. To make this possible, it [sends all your internet traffic through an encrypted connection](https://riseup.net/en/vpn/how-vpn-works) to riseup.net, where it then goes out onto the public internet.
>
> Unlike most other VPN providers, Riseup does not log your IP address.
>
> Riseup has a VPN client called **RiseupVPN**. This VPN client is super easy to use! You just install it and run it—no configuration, no account registration.

There is already a [riseup-vpn](https://aur.archlinux.org/packages/riseup-vpn) package in AUR. But there a few things I don't like:

- the software is pretty bloated (unnecessary GUI, I got `could not find polkit agent` error messages)
- sthe autostart feature just put's a file into `~/.config/autostart` which doesn't work with i3
- the VPN does not use the best available crypto/ciphers (TLS1.2 instead of TLS1.3)
- it's not possible to exclude routes from the VPN

The riseup-vpn-configurator is a simple command line tool that tries to solve these problems. It generates an OpenVPN configuration file that can be used by `systemctl`.

# Installation

Please don't install it as user and run it as root, as this makes an attacker very easy to escalate privileges.

# Installation (as a dev)

We need to run the tool with root permissions (for example to write to /etc). Running the tests also need root privileges (because we use chown). Therefore, I recommend running the dev environment also as root user.

```bash
root@linbox:tmp git clone https://github.com/kmille/riseup-vpn-configurator.git
root@linbox:tmp cd riseup-vpn-configurator
root@linbox:riseup-vpn-configurator poetry install
poetry run python riseup_vpn_configurator/__init__.py --help
root@linbox:riseup-vpn-configurator poetry run pytest -v -s -x --pdb
```

# How to use it

# How it works

The code for the RiseupVPN Linux client can be found [here](https://0xacab.org/leap/bitmask-vpn). It uses OpenVPN. Everyone uses the same client certificate/key to authenticate. The client certificate is only valid for 90 days. The VPN gateway list and client certificate can be fetched by a public API.



- systemctl start openvpn-client@riseup
- systemctl enable openvpn-client@riseup

# Monitoring with py3status

If you use [py3status](https://github.com/ultrabug/py3status) as i3bar implementation, you can use [monitor_riseupvpn.py](/monitor_riseupvpn.py) for monitoring.

# Known issues

RiseupVPN does not support IPv6. It's routed over the tunnel but then gets blocked. Also, the VPN hangs after suspend ([see Arch Wiki](https://wiki.archlinux.org/title/OpenVPN#Client_daemon_not_reconnecting_after_suspend)). To solve this issue, the AUR package uses [openvpn-reconnect](https://aur.archlinux.org/packages/openvpn-reconnect) as a dependency.

# Ressources
- https://riseup.net/de/vpn
- https://riseup.net/de/vpn/linux
- https://0xacab.org/leap/bitmask-vpn
- https://gitlab.com/nitrohorse/bitmask-openvpn-generator

[![tests](https://github.com/kmille/riseup-vpn-configurator/actions/workflows/tests.yaml/badge.svg?branch=main)](https://github.com/kmille/riseup-vpn-configurator/actions/workflows/tests.yaml)
![Python 3.6](https://img.shields.io/badge/python-%3E=3.5-blue.svg)
![license](https://img.shields.io/github/license/kmille/riseup-vpn-configurator?color=green)
![latest tag](https://img.shields.io/github/v/tag/kmille/riseup-vpn-configurator?sort=semver)
![pypi-version](https://img.shields.io/pypi/v/riseup-vpn-configurator)
![pypi-downloads](https://img.shields.io/pypi/dm/riseup-vpn-configurator)
# riseup-vpn-configurator

> Riseup offers Personal VPN service for censorship circumvention, location anonymization and traffic encryption. To make this possible, it [sends all your internet traffic through an encrypted connection](https://riseup.net/en/vpn/how-vpn-works) to riseup.net, where it then goes out onto the public internet.
>
> Unlike most other VPN providers, Riseup does not log your IP address.
>
> Riseup has a VPN client called **RiseupVPN**. This VPN client is super easy to use! You just install it and run it—no configuration, no account registration.

There is already a [riseup-vpn](https://aur.archlinux.org/packages/riseup-vpn) package in AUR. But there a few things I don't like:

- the software is pretty bloated (unnecessary GUI, I got `could not find polkit agent` error messages)
- the autostart feature just put's a file into `~/.config/autostart` which doesn't work with i3
- the VPN does not use the best available crypto/ciphers (TLS1.2 instead of TLS1.3)
- it's not possible to exclude routes from the VPN

The riseup-vpn-configurator is a simple command line tool that tries to solve these problems. It generates an OpenVPN configuration file that can be used by `systemctl`.

# Installation

Please don't install it as user and run it as root, as this makes it very easy for an attacker to escalate privileges. You can install the [Arch Linux AUR package](https://aur.archlinux.org/packages/riseup-vpn-configurator) or use it with `pip install --user riseup-vpn-configurator` as root. Check out the `How to use it` below to get the VPN up and running. You can start RiseupVPN with `systemctl start openvpn-client@riseup` and autostart it with `systemctl enable openvpn-client@riseup`. Please keep in mind that the client certificate is only valid for 90 and you have to update it manually.

```bash
kmille@linbox:~ riseup-vpn-configurator --help
usage: riseup-vpn-configurator [-h] [-v] [-d] [-u] [--uninstall] [-l] [-b] [-c] [-g] [-s] [--version]

options:
  -h, --help            show this help message and exit
  -v, --verbose         show verbose output
  -d, --default-config  print default config file risup-vpn.yaml
  -u, --update          update gateway list and client certificate/key
  --uninstall           remove all files
  -l, --list-gateways   show available VPN server
  -b, --benchmark       use with --list - pings the gateway and shows the latency
  -c, --check-config    check syntax of /etc/riseup-vpn.yaml. Generates default config
  -g, --generate-config
                        Generate openvpn config (/etc/openvpn/client/riseup.conf)
  -s, --status          show current state of riseup-vpn
  --version             show version
```

Default config file `/etc/riseup-vpn.yaml`
```yaml
---
# /etc/riseup-vpn.yaml

server: vpn07-par.riseup.net
protocol: udp
port: 53

# your local subnet is excluded by default
excluded_routes:
  - 1.1.1.1
  - 192.168.123.0/24
```

# How to use it
[![asciicast](https://asciinema.org/a/559611.svg)](https://asciinema.org/a/559611)
# Installation (as a dev)

We need to run the tool with root permissions (for example to write to /etc). Running the tests also need root privileges (because we use chown). Therefore, I recommend running the dev environment also as root user.

```bash
root@linbox:tmp git clone https://github.com/kmille/riseup-vpn-configurator.git
root@linbox:tmp cd riseup-vpn-configurator
root@linbox:riseup-vpn-configurator poetry install
poetry run python riseup_vpn_configurator/__init__.py --help
root@linbox:riseup-vpn-configurator poetry run pytest -v -s -x --pdb
root@linbox:riseup-vpn-configurator poetry run flake8 --ignore=E501 riseup_vpn_configurator/
root@linbox:riseup-vpn-configurator poetry run mypy riseup_vpn_configurator/
```

# How it works

The code for the RiseupVPN Linux client can be found [here](https://0xacab.org/leap/bitmask-vpn). It uses OpenVPN. Everyone uses the same client certificate/key to authenticate. The client certificate is only valid for 90 days. The VPN gateway list and client certificate can be fetched by a public API.

# Monitoring with py3status

If you use [py3status](https://github.com/ultrabug/py3status) as i3bar implementation, you can use [monitor_riseupvpn.py](/monitoring/monitor_riseupvpn.py) for monitoring.

# Known issues

RiseupVPN does not support IPv6. It's routed over the tunnel but then gets blocked. Also, the VPN hangs after suspend ([see Arch Wiki](https://wiki.archlinux.org/title/OpenVPN#Client_daemon_not_reconnecting_after_suspend)). To solve this issue, the AUR package uses [openvpn-reconnect](https://aur.archlinux.org/packages/openvpn-reconnect) as a dependency.

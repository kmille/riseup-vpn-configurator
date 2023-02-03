#!/usr/bin/env python3
import sys
import os
import argparse
import json
import yaml
from jinja2 import Template
from pathlib import Path
import requests
from ipaddress import ip_network
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder
import psutil
#from subprocess import Popen, PIPE

import logging
FORMAT = "%(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)

logging.getLogger("urllib3").setLevel(logging.WARNING)


working_dir = Path("/opt/riseup-vpn")
api_ca_cert_file = working_dir / Path("api-ca.pem")

ca_cert_file = working_dir / Path("ca.pem")
cert_file = working_dir / Path("cert.pem")
key_file = working_dir / Path("key.pem")

gateway_json = working_dir / Path("gateways.json")

config_file = Path("/etc/riseup-vpn.yaml")
ovpn_file = Path("/etc/openvpn/client/riseup.conf")

GATEWAYS_API_URL = "https://api.black.riseup.net/1/configs/eip-service.json"
PROVIDER_API_URL = "https://riseup.net/provider.json"
VPN_CA_CERT_URL = "https://black.riseup.net/ca.crt"
VPN_CLIENT_CREDENTIALS_URL = "https://api.black.riseup.net/1/cert"


def cache_api_ca_cert():
    logging.debug("Updating riseup.net ca certificate")
    logging.debug(f"Fetching riseup.net vpn metadata from {PROVIDER_API_URL}")
    resp = requests.get(PROVIDER_API_URL)
    j = resp.json()
    logging.debug(f"Fetching ca certificate from {j['ca_cert_uri']}")
    resp = requests.get(j['ca_cert_uri'])
    ca_cert_file.write_text(resp.text)
    logging.debug(f"Sucessfully cached ca certificate to {ca_cert_file}")


def update_gateways():
    """
    curl https://api.black.riseup.net/1/configs/eip-service.json
    """
    logging.info("Updating riseup.net gateway list")
    cache_api_ca_cert()
    logging.debug(f"Fetching gateways from {GATEWAYS_API_URL}")
    resp = requests.get(GATEWAYS_API_URL, verify=str(ca_cert_file))
    gateway_json.write_text(resp.text)
    logging.info(f"Sucessfully saved riseup.net gateways to {gateway_json}")


def update_ca_certificate():
    """
    curl https://black.riseup.net/ca.crt
    """
    logging.info("Updating ca certificate")
    resp = requests.get(VPN_CA_CERT_URL)
    ca_cert_file.write_text(resp.text)
    logging.debug(f"Sucessfully saved ca certificate to {ca_cert_file}")


def update_client_credentials():
    """
    curl https://black.riseup.net/ca.crt > ca.crt
    curl https://api.black.riseup.net/1/cert --cacert ca.crt
    """
    logging.debug("Updating client certificate/key")
    resp = requests.get(VPN_CLIENT_CREDENTIALS_URL, verify=str(ca_cert_file))
    SEPERATOR = "-----BEGIN CERTIFICATE-----"
    parts = resp.text.split(SEPERATOR)
    key = parts[0].strip()
    key_file.write_text(key)
    cert = f"{SEPERATOR}{parts[1]}".strip()
    cert_file.write_text(cert)
    logging.info(f"Sucessfully saved client certificate to {cert_file}")
    key_file.write_text(key)
    logging.info(f"Sucessfully saved client key to {key_file}")


def list_gateways():
    print("TODO: fix view SORT")
    with open(gateway_json) as f:
        j = json.load(f)
    gateways = j['gateways']
    out = ""
    for gw in gateways:
        out += f"{gw['host']} {gw['location']} {gw['ip_address']} ("
        for transport in gw['capabilities']['transport']:
            if transport['type'] == "openvpn":
                protocols = ",".join(transport['protocols'])
                ports = ",".join(transport['ports'])
                out += f"protocols={protocols} ports={ports})\n"
    print(out.strip())


def get_excluded_routes():
    with open(config_file) as f:
        y = yaml.safe_load(f)
    out = ""
    for excluded_route in y['excluded_routes']:
        try:
            net = ip_network(excluded_route, strict=False)
        except ValueError as e:
            logging.error(e)
            sys.exit(1)
        out += f"route {net.network_address} {net.netmask} net_gateway\n"
    return out.strip()


def check_config_file():
    logging.debug(f"Checking configuration file {config_file}")
    with open(config_file) as f:
        y = yaml.safe_load(f)

    for c in ("gateway_method", "server", "location", "protocol", "port", "excluded_routes"):
        if c not in y.keys():
            logging.error(f"Error checking configuration file ({config_file}): '{c}' not specified")
            sys.exit(1)

    if y["gateway_method"] not in ("server", "location", "random"):
        logging.error(f"Error checking configuration file ({config_file}): 'gateway_configuration' must be one of the values server|location|random (specified was '{y['gateway_method']}')")
        sys.exit(1)

    if y["protocol"] not in ("tcp", "udp"):
        logging.error(f"Error checking configuration file ({config_file}): 'protocol' must be one of the values tcp|udp (specified was '{y['protocol']}')")
        sys.exit(1)
    if not str(y["port"]).isnumeric():
        logging.error(f"Error checking configuration file ({config_file}): 'port' must be numeric (specified was '{y['port']}')")
        sys.exit(1)

    for route in y['excluded_routes']:
        try:
            _ = ip_network(route, strict=False)
        except ValueError as e:
            logging.error(f"Error checking configuration file ({config_file}): exclude route '{route}' is invalid: {e}")
            sys.exit(1)
    logging.info("Configuration file: OK")


def get_openvpn_dynamic_server_configuration():
    with open(gateway_json) as f:
        j = json.load(f)
    out = ""
    for key, value in j['openvpn_configuration'].items():
        # https://community.openvpn.net/openvpn/wiki/DeprecatedOptions#Option:--tun-ipv6Status:Ignoredpendingremoval
        if key == "tun-ipv6":
            continue
        out += f"{key} {value}\n"
    out = (out.strip())
    return out


def get_server_info():
    with open(config_file) as f:
        y = yaml.safe_load(f)
    #with open(gateway_json) as f:
    #    j = json.load(f)
    #gateways = j['gateways']
    #gw = gateways[0]
    return {
        'hostname': y['server'],
        'proto': y['protocol'],
        'port': y['port'],
        'location': 'Seatle TODO: this is hard coded'
    }


def generate_configuration():
    ovpn_template = """client
tls-client
dev tun

# BEGIN DYNAMIC SERVER CONFIGURATION
remote {{ server_info['hostname'] }} {{ server_info['port'] }}
proto {{ server_info['proto'] }}
verify-x509-name {{ server_info['hostname'].split(".")[0] }} name

{{ dynamic_config }}
# END DYNAMIC SERVER CONFIGURATION

resolv-retry infinite
nobind
verb 3
persist-key
persist-tun
reneg-sec 0
pull
auth-nocache

#script-security 2
#up /etc/openvpn/update-resolv-conf
#down /etc/openvpn/update-resolv-conf

tls-version-min 1.2
redirect-gateway ipv6
remote-cert-tls server
remote-cert-eku "TLS Web Server Authentication"

# BEGIN EXCLUDE ROUTES
route 1.2.3.4 255.255.255.255 net_gateway
{{ excluded_routes }}
# END EXCLUDE ROUTES

ca {{ ca_cert_file }}
cert {{ cert_file }}
key {{ key_file }}"""

    server_info = get_server_info()
    dynamic_config = get_openvpn_dynamic_server_configuration()
    excluded_routes = get_excluded_routes()
    t = Template(ovpn_template)
    config = t.render(server_info=server_info,
                      dynamic_config=dynamic_config,
                      excluded_routes=excluded_routes,
                      ca_cert_file=ca_cert_file,
                      cert_file=cert_file,
                      key_file=key_file)
    ovpn_file.write_text(config)
    logging.info(f"Sucessfully saved riseup.vpn configuration file to {ovpn_file}")


def show_status():
    check_config_file()

    if ca_cert_file.exists():
        logging.info("CA certificate: OK")
    else:
        logging.error("CA certificate not found. You can get it with --update")

    if key_file.exists():
        logging.info("Client key: OK")
    else:
        logging.error("Client key not found. You can get it with --update")

    if not cert_file.exists():
        logging.error("Client certificate not found. You can get it with --update")
    else:
        with open(cert_file) as f:
            substrate = pem.readPemFromFile(f)
            cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
        notBefore = next(cert['tbsCertificate']['validity']['notBefore'].values()).asDateTime
        notAfter = next(cert['tbsCertificate']['validity']['notAfter'].values()).asDateTime
        logging.info(f"Client certificate is valid from {notBefore.strftime('%d.%m.%Y')} to {notAfter.strftime('%d.%m.%Y')}")

    if gateway_json.exists():
        logging.info("VPN gateway list: OK")
    else:
        logging.error("VPN gateway not found. You can get it with --update")

    openvpn_found = False
    for proc in psutil.process_iter():
        if "openvpn" in proc.name():
            openvpn_found = True
            logging.info(f"Found a running openvpn process: '{' '.join(proc.cmdline())}' with pid {proc.pid}")
    if not openvpn_found:
        logging.warning("No running openvpn process found")

    resp = requests.get("https://api4.ipify.org?format=json")
    logging.info(f"Your IPv4 address: {resp.json()['ip']}")
    #resp = requests.get("https://api6.ipify.org?format=json")
    #logging.info(f"Your IPv6 address: {resp.json()['ip']}")


def check_root_permissions():
    if os.getuid() != 0:
        logging.error("This scripts needs to be executed with root permission.")
        sys.exit(1)


#def enable_riseup_vpn():
#    check_config_file()
#    with open(config_file) as f:
#        y = yaml.safe_load(f)
#    config = Path(y['config_location']).stem
#
#    def execute(x):
#        logging.debug(f"Executing: '{' '.join(x)}'")
#        p = Popen(x, stdout=PIPE, stderr=PIPE)
#        p.wait()
#        stdout, stderr = p.communicate()
#        if p.returncode != 0:
#            logging.error(f"{stderr.decode()}")
#
#    #execute(["systemctl", "enable", f"openvpn-client@{config}.service"])
#    #execute(["systemctl", "start", f"openvpn-client@{config}.service"])
#    #execute(["systemctl", "stop", f"openvpn-client@{config}.service"])
#    #execute(["systemctl", "disable", f"openvpn-client@{config}.service"])

def check_directories():
    import pwd
    import grp

    if not working_dir.exists():
        working_dir.mkdir(0o700)

    uid = pwd.getpwnam("openvpn").pw_uid
    gid = grp.getgrnam("openvpn").gr_gid
    os.chown(working_dir, uid, gid)

    if not config_file.exists():
        logging.error(f"Could not find config file {config_file}")
        sys.exit(1)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", help="show verbose output")
    parser.add_argument("-u", "--update", action="store_true", help="update gateway list and client certificate/key")
    parser.add_argument("-l", "--list-gateways", action="store_true", help="show available VPN server")
    parser.add_argument("-c", "--check-configuration", action="store_true", help=f"check syntax of {config_file}")
    parser.add_argument("-g", "--generate-configuration", action="store_true")
    parser.add_argument("-s", "--status", action="store_true", help="show current state of riseup-vpn")
    #parser.add_argument("-e", "--enable", action="store_true", help="Start and enable riseup-vpn")
    #parser.add_argument("-d", "--disable", action="store_true", help="Stop and disable riseup-vpn")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    check_root_permissions()
    check_directories()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.update:
        update_gateways()
        update_ca_certificate()
        update_client_credentials()
    elif args.list_gateways:
        list_gateways()
    elif args.generate_configuration:
        check_config_file()
        generate_configuration()
    elif args.check_configuration:
        check_config_file()
    elif args.status:
        show_status()
    #elif args.enable:
    #    enable_riseup_vpn()


if __name__ == '__main__':
    main()

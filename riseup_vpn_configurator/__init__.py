#!/usr/bin/env python3
import sys
import os
import logging
import argparse
import json
import yaml
import subprocess
import pwd
import grp
from jinja2 import Template
from pathlib import Path
import requests
from ipaddress import ip_network
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder
import psutil
from icmplib import ping, ICMPLibError
import shutil
import socket
from typing import Optional, NoReturn

FORMAT = "%(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)
# logging.getLogger("urllib3").setLevel(logging.WARNING)

working_dir = Path("/opt/riseup-vpn")
api_ca_cert_file = working_dir / Path("api-ca.pem")
gateway_json = working_dir / Path("gateways.json")

ca_cert_file = working_dir / Path("vpn-ca.pem")
cert_file = working_dir / Path("cert.pem")
key_file = working_dir / Path("key.pem")

config_file = Path("/etc/riseup-vpn.yaml")
ovpn_file = Path("/etc/openvpn/client/riseup.conf")

GATEWAYS_API_URL = "https://api.black.riseup.net/3/config/eip-service.json"
PROVIDER_API_URL = "https://riseup.net/provider.json"
VPN_CA_CERT_URL = "https://black.riseup.net/ca.crt"
VPN_CLIENT_CREDENTIALS_URL = "https://api.black.riseup.net/3/cert"

VERIFY_SSL_CERTIFICATE = True


def get_rtt(ip: str) -> float:
    try:
        resp = ping(ip, timeout=2, count=5, interval=0.5)
        logging.debug(f"Getting rtt for{resp}")
        # ping 1.1.1.1brokenip returns 0.0 and does not raise an exception ...?
        if resp.avg_rtt == 0.0:
            return 9000.0
        return resp.avg_rtt
    except ICMPLibError as e:
        logging.warning(f"Error getting rtt for {ip}: {e}")
        return 9000.0


def cache_api_ca_cert() -> None:
    logging.debug("Updating riseup.net API API CA certificate")
    logging.debug(f"Fetching riseup.net VPN metadata from {PROVIDER_API_URL}")
    try:
        resp = requests.get(PROVIDER_API_URL, verify=VERIFY_SSL_CERTIFICATE)
        resp.raise_for_status()
        j = resp.json()
        logging.debug(f"Fetching API CA certificate from {j['ca_cert_uri']}")
        resp = requests.get(j['ca_cert_uri'], verify=VERIFY_SSL_CERTIFICATE)
        resp.raise_for_status()
        api_ca_cert_file.write_text(resp.text)
    except (requests.RequestException, KeyError) as e:
        logging.error(e)
        sys.exit(1)
    fix_file_permissions(api_ca_cert_file)
    logging.info(f"Sucessfully cached API CA certificate to {api_ca_cert_file}")


def update_gateways() -> None:
    """
    curl https://api.black.riseup.net/1/configs/eip-service.json
    """
    logging.info("Updating VPN gateway list")
    cache_api_ca_cert()
    logging.debug(f"Fetching gateways from {GATEWAYS_API_URL}")
    try:
        # resp = requests.get(GATEWAYS_API_URL, verify=api_ca_cert_file.as_posix())
        resp = requests.get(GATEWAYS_API_URL)
        resp.raise_for_status()
        gateway_json.write_text(resp.text)
    except requests.RequestException as e:
        logging.error(e)
        sys.exit(1)
    fix_file_permissions(gateway_json)
    logging.info(f"Sucessfully saved VPN gateway list to {gateway_json}")


def update_vpn_ca_certificate() -> None:
    """
    curl https://black.riseup.net/ca.crt
    """
    logging.info("Updating VPN CA certificate")
    try:
        resp = requests.get(VPN_CA_CERT_URL, verify=VERIFY_SSL_CERTIFICATE)
        resp.raise_for_status()
        if "-----BEGIN CERTIFICATE-----" not in resp.text or \
           "-----END CERTIFICATE-----" not in resp.text:
            raise ValueError(f"Response is invalid\nURL: {VPN_CA_CERT_URL}\nResponse:\n{resp.text}")
        ca_cert_file.write_text(resp.text)
    except (requests.RequestException, ValueError) as e:
        logging.error(e)
        sys.exit(1)
    fix_file_permissions(ca_cert_file)
    logging.info(f"Sucessfully saved VPN CA certificate to {ca_cert_file}")


def update_vpn_client_credentials() -> None:
    """
    curl https://black.riseup.net/ca.crt > ca.crt
    curl https://api.black.riseup.net/1/cert --cacert ca.crt
    """
    logging.info("Updating client certificate/key")
    try:
        # resp = requests.get(VPN_CLIENT_CREDENTIALS_URL, verify=api_ca_cert_file.as_posix())
        resp = requests.get(VPN_CLIENT_CREDENTIALS_URL)
        resp.raise_for_status()
        SEPERATOR = "-----BEGIN CERTIFICATE-----"
        parts = resp.text.split(SEPERATOR)
        key = parts[0].strip()
        if "-----BEGIN RSA PRIVATE KEY-----" not in key or \
                "-----END RSA PRIVATE KEY-----" not in key:
            raise ValueError(f"Private key could not be found:\n{resp.text}")

        key_file.write_text(key)
        fix_file_permissions(key_file)
        logging.info(f"Sucessfully saved VPN client key to {key_file}")

        cert = f"{SEPERATOR}{parts[1]}".strip()
        if "-----BEGIN CERTIFICATE-----" not in cert or \
                "-----END CERTIFICATE-----" not in cert:
            raise ValueError(f"Certificate could not be found:\n{resp.text}")

        cert_file.write_text(cert)
        fix_file_permissions(cert_file)
        logging.info(f"Sucessfully saved VPN client certificate to {cert_file}")
    except (requests.RequestException, ValueError) as e:
        logging.error(e)
        sys.exit(1)


def list_gateways(bench: bool) -> None:
    if not gateway_json.exists():
        logging.error(f"Could not find gateway list ({gateway_json}). You can get it with --update")
        sys.exit(1)

    with open(gateway_json) as f:
        j = json.load(f)
    if bench:
        logging.info("Listing VPN gateways with rtt (round-trip-time). Plase turn off the VPN before to get proper results.")
        for gw in j['gateways']:
            gw['rtt'] = get_rtt(gw['ip_address'])
        gateways = sorted(j['gateways'], key=lambda gw: gw['rtt'])
    else:
        gateways = sorted(j['gateways'], key=lambda gw: gw['location'])

    out = ""
    for gw in gateways:
        out += f"{gw['host']} location={gw['location']:<13} ip={gw['ip_address']:<15} "
        if bench:
            rtt_formatted = f"{gw['rtt']} ms "
            out += f"rtt={rtt_formatted:<11}"
        for transport in gw['capabilities']['transport']:
            if transport['type'] == "openvpn":
                protocols = ",".join(transport['protocols'])
                ports = ",".join(transport['ports'])
                out += f"protocols={protocols:<7} ports={ports}\n"
    print(out.strip())


def get_excluded_routes() -> str:
    with open(config_file) as f:
        y = yaml.safe_load(f)
    out = ""
    for host in y['excluded_routes']:
        try:
            net = ip_network(host, strict=False)
            out += f"route {net.network_address} {net.netmask} net_gateway\n"
            logging.debug(f"Added '{net.network_address}' as an exception")
        except ValueError:
            try:
                _, _, ip_addresses = socket.gethostbyname_ex(host)
                for ip_address in ip_addresses:
                    logging.debug(f"Resolved '{host}' to '{ip_address}'. Added as an exception")
                    out += f"route {ip_address} 255.255.255.255 net_gateway\n"
            except socket.gaierror as e:
                logging.error(f"Error parsing {host} in excluded_routes (not a ipaddress/network or hostname): {e}")
                sys.exit(1)
    return out.strip()


def get_openvpn_user_group() -> tuple[str, str]:
    vpn_user = vpn_group = "openvpn"

    with open(config_file) as f:
        try:
            y = yaml.safe_load(f)
        except yaml.scanner.ScannerError as e:
            logging.error(f"Could not parse yaml file: {e}")
            sys.exit(1)
    if "user" in y:
        vpn_user = y["user"]
    if "group" in y:
        vpn_group = y["group"]
    return vpn_user, vpn_group


def check_config_file() -> None:
    logging.debug(f"Checking configuration file {config_file}")

    with open(config_file) as f:
        try:
            y = yaml.safe_load(f)
        except yaml.scanner.ScannerError as e:
            logging.error(f"Could not parse yaml file: {e}")
            sys.exit(1)
    if not y or type(y) is not dict:
        logging.error(f"Could not parse config file {config_file}")
        print_default_config(1)

    for c in ("server", "protocol", "port", "excluded_routes"):
        if c not in y.keys():
            logging.error(f"Error checking configuration file ({config_file}): '{c}' not specified")
            sys.exit(1)

    if y["protocol"] not in ("tcp", "udp"):
        logging.error(f"Error checking configuration file ({config_file}): 'protocol' must be one of the values tcp|udp (specified was '{y['protocol']}')")
        sys.exit(1)
    if not str(y["port"]).isnumeric():
        logging.error(f"Error checking configuration file ({config_file}): 'port' must be numeric (specified was '{y['port']}')")
        sys.exit(1)

    for host in y['excluded_routes']:
        try:
            _ = ip_network(host, strict=False)
        except ValueError:
            try:
                socket.gethostbyname(host)
            except socket.gaierror as e:
                logging.error(f"Error checking configuration file ({config_file}): exclude route '{host}' is not an ip address/network or a valid hostname:: {e}")
                sys.exit(1)
    logging.info("Configuration file: OK")


def get_server_info() -> Optional[dict]:
    with open(config_file) as f:
        config = yaml.safe_load(f)
    with open(gateway_json) as f:
        j = json.load(f)
    gateways = j['gateways']
    for gw in gateways:
        if gw['host'] == config['server']:
            return {
                'hostname': gw['host'],
                'ip_address': gw['ip_address'],
                'proto': config['protocol'],
                'port': config['port'],
                'location': gw['location'],
            }
    logging.error(f"Gateway '{config['server']}' not found in gateway list. Please check with --list")
    sys.exit(1)


def generate_configuration() -> None:
    def check_file_exists(file: Path) -> None:
        if not file.exists():
            logging.error(f"File ({file}) not found. You can get it by using --update")
            sys.exit(1)

    check_file_exists(ca_cert_file)
    check_file_exists(cert_file)
    check_file_exists(key_file)

    ovpn_template = """# reference manual: https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/
client
dev tun

remote {{ server_info['ip_address'] }} {{ server_info['port'] }} # {{ server_info['hostname'] }} in {{ server_info['location'] }}
proto {{ server_info['proto'] }}
verify-x509-name {{ server_info['hostname'].split(".")[0] }} name

cipher AES-256-GCM
tls-version-min 1.3

resolv-retry infinite
keepalive 10 60
nobind
verb 3

#script-security 2
#up /etc/openvpn/update-resolv-conf
#down /etc/openvpn/update-resolv-conf

remote-cert-tls server
remote-cert-eku "TLS Web Server Authentication"

# BEGIN EXCLUDE ROUTES
{{ excluded_routes }}
# END EXCLUDE ROUTES

ca {{ ca_cert_file }}
cert {{ cert_file }}
key {{ key_file }}"""

    server_info = get_server_info()
    excluded_routes = get_excluded_routes()
    t = Template(ovpn_template)
    config = t.render(server_info=server_info,
                      excluded_routes=excluded_routes,
                      ca_cert_file=ca_cert_file,
                      cert_file=cert_file,
                      key_file=key_file)
    ovpn_file.write_text(config)
    fix_file_permissions(ovpn_file)
    logging.info(f"Sucessfully saved RiseupVPN configuration file to {ovpn_file}")


def show_status() -> None:
    if ca_cert_file.exists():
        logging.info("CA certificate: OK")
    else:
        logging.warning("CA certificate not found. You can get it with --update")

    if key_file.exists():
        logging.info("Client key: OK")
    else:
        logging.warning("Client key not found. You can get it with --update")

    if not cert_file.exists():
        logging.warning("Client certificate not found. You can get it with --update")
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
        logging.warning("VPN gateway not found. You can get it with --update")

    if ovpn_file.exists():
        logging.info(f"VPN configuration ({ovpn_file}): OK")
    else:
        logging.warning(f"VPN configuration ({ovpn_file}) not found. You can get it with --generate-config")

    openvpn_found = False
    for proc in psutil.process_iter():
        if "openvpn" in proc.name():
            openvpn_found = True
            logging.info(f"Found a running openvpn process: '{' '.join(proc.cmdline())}' with pid {proc.pid}")
    if not openvpn_found:
        logging.warning("No running openvpn process found")

    try:
        resp = requests.get("https://api4.ipify.org?format=json", timeout=5)
        resp.raise_for_status()
        logging.info(f"Your IPv4 address: {resp.json()['ip']}")
    except requests.RequestException as e:
        logging.warning(f"Error finding your public IPv4 address: {e}")

    logging.debug("Start/Stop Riseup-VPN")
    logging.debug("systemctl start openvpn-client@riseup")
    logging.debug("systemctl stop openvpn-client@riseup")
    logging.debug("Autostart Riseup-VPN")
    logging.debug("systemctl enable openvpn-client@riseup")
    logging.debug("systemctl disable openvpn-client@riseup")


def check_root_permissions() -> None:
    if os.getuid() != 0:
        logging.error("This scripts needs to be executed with root permission.")
        sys.exit(1)


def fix_file_permissions(file: Path) -> None:
    vpn_user, vpn_group = get_openvpn_user_group()
    try:
        uid = pwd.getpwnam(vpn_user).pw_uid
        gid = grp.getgrnam(vpn_group).gr_gid
    except KeyError as e:
        logging.error(f"Could not find user/group: {e}. You can adjust user/group in {config_file}")
        sys.exit(1)
    os.chown(file, uid, gid)
    file.chmod(0o600)


def print_default_config(return_code: int) -> NoReturn:
    config_template = Path(__file__).parent / config_file.name
    print(config_template.read_text())
    sys.exit(return_code)


def check_working_directory() -> None:
    if not working_dir.exists():
        vpn_user, vpn_group = get_openvpn_user_group()
        try:
            uid = pwd.getpwnam(vpn_user).pw_uid
            gid = grp.getgrnam(vpn_group).gr_gid
        except KeyError as e:
            logging.error(f"Could not find user/group: {e}. You can adjust user/group in {config_file}")
            sys.exit(1)
        working_dir.mkdir(0o700)
        os.chown(working_dir, uid, gid)

    if not config_file.exists():
        logging.error(f"Could not find config file {config_file}. Use --default-config for the default config file")
        sys.exit(1)


def uninstall() -> NoReturn:
    def delete(file: Path) -> None:
        try:
            if file.resolve().is_file():
                file.unlink()
                logging.info(f"Deleted file {file}")
            else:
                shutil.rmtree(file)
                logging.info(f"Deleted directory {file}")
        except FileNotFoundError:
            pass

    delete(working_dir)
    delete(config_file)
    delete(ovpn_file)
    sys.exit(0)


def print_error_log():
    logging.info("Printing debug log")
    try:
        p = subprocess.run(["journalctl", "-u", "openvpn-client@riseup", "-n", "50"], capture_output=True)
        logging.info(p.stdout.decode())
    except subprocess.CalledProcessError as e:
        logging.error(f"Could not get logs for riseup vpn: {e}")


def start_openvpn():
    try:
        subprocess.run(["systemctl", "start", "openvpn-client@riseup"], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Could not start riseup vpn: {e}")
        print_error_log()
    else:
        logging.info("riseupvpn sucessfully started")


def stop_openvpn():
    try:
        subprocess.run(["systemctl", "stop", "openvpn-client@riseup"], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Could not stop riseup vpn: {e}")
        print_error_log()
    else:
        logging.info("riseupvpn sucessfully stopped")


def show_version():
    from importlib.metadata import version
    app_name = "riseup-vpn-configurator"
    logging.info(f"Running {app_name} v{version(app_name)}")
    sys.exit()


def main() -> None:

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", help="show verbose output")
    parser.add_argument("--no-check-certificate", action="store_true", help="skip ssl certificate check (used by --update to get the config/client private key from the API)")
    parser.add_argument("-d", "--default-config", action="store_true", help="print default config file risup-vpn.yaml")
    parser.add_argument("-u", "--update", action="store_true", help="update gateway list and client certificate/key")
    parser.add_argument("--uninstall", action="store_true", help=f"remove all files in {working_dir}")
    parser.add_argument("-l", "--list-gateways", action="store_true", help="show available VPN server")
    parser.add_argument("-b", "--benchmark", action="store_true", help="use with --list - pings the gateway and shows the latency")
    parser.add_argument("-c", "--check-config", action="store_true", help=f"check syntax of {config_file}. Generates default config")
    parser.add_argument("-g", "--generate-config", action="store_true", help=f"Generate openvpn config ({ovpn_file})")
    parser.add_argument("-s", "--status", action="store_true", help="show current state of riseup-vpn")
    parser.add_argument("--start", action="store_true", help="starts openvpn service")
    parser.add_argument("--stop", action="store_true", help="stops openvpn service")
    parser.add_argument("--restart", action="store_true", help="restarts openvpn service")
    parser.add_argument("--log", action="store_true", help="show systemd log")
    parser.add_argument("--version", action="store_true", help="show version")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.no_check_certificate:
        global VERIFY_SSL_CERTIFICATE
        VERIFY_SSL_CERTIFICATE = False

    elif args.version:
        show_version()
    elif args.default_config:
        print_default_config(0)

    check_root_permissions()

    if args.uninstall:
        uninstall()

    check_working_directory()

    if args.update:
        update_gateways()
        update_vpn_ca_certificate()
        update_vpn_client_credentials()
    elif args.check_config:
        check_config_file()
    elif args.list_gateways:
        list_gateways(args.benchmark)
    elif args.generate_config:
        check_config_file()
        generate_configuration()
    elif args.status:
        check_config_file()
        show_status()
    elif args.start:
        start_openvpn()
    elif args.stop:
        stop_openvpn()
    elif args.restart:
        stop_openvpn()
        start_openvpn()
    elif args.log:
        print_error_log()


if __name__ == '__main__':
    main()

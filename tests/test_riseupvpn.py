import os
import pytest
from pathlib import Path
import tempfile
import logging

import riseup_vpn_configurator


class TestRiseupVPN:

    def check_permissions_of_file(self, file: Path) -> bool:
        perm = os.stat(str(file))
        assert perm.st_mode == 0o100600
        assert file.owner() == riseup_vpn_configurator.VPN_USER
        assert file.group() == riseup_vpn_configurator.VPN_USER
        return True

    def setup_class(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        working_dir = Path(self.temp_dir.name)

        riseup_vpn_configurator.working_dir = Path("/opt/riseup-vpn")
        riseup_vpn_configurator.api_ca_cert_file = working_dir / Path("api-ca.pem")
        riseup_vpn_configurator.gateway_json = working_dir / Path("gateways.json")
        riseup_vpn_configurator.ca_cert_file = working_dir / Path("vpn-ca.pem")
        riseup_vpn_configurator.cert_file = working_dir / Path("cert.pem")
        riseup_vpn_configurator.key_file = working_dir / Path("key.pem")
        riseup_vpn_configurator.config_file = working_dir / Path("riseup-vpn.yaml")
        riseup_vpn_configurator.ovpn_file = working_dir / Path("riseup.conf")

    def teardown_class(self):
        self.temp_dir.cleanup()

    def test_cache_api_ca_cert(self, caplog):
        from riseup_vpn_configurator import cache_api_ca_cert
        caplog.set_level(logging.INFO)

        cache_api_ca_cert()
        assert riseup_vpn_configurator.api_ca_cert_file.exists()
        assert "Sucessfully" in caplog.text
        assert self.check_permissions_of_file(riseup_vpn_configurator.api_ca_cert_file)

        api_ca_cert = riseup_vpn_configurator.api_ca_cert_file.read_text()
        assert api_ca_cert.startswith("-----BEGIN CERTIFICATE-----")
        assert api_ca_cert.strip().endswith("-----END CERTIFICATE-----")

    def test_update_gateways(self, caplog):
        import json
        from riseup_vpn_configurator import update_gateways
        caplog.set_level(logging.INFO)

        update_gateways()

        assert riseup_vpn_configurator.gateway_json.exists()
        assert "Sucessfully saved VPN gateway list" in caplog.text
        assert self.check_permissions_of_file(riseup_vpn_configurator.gateway_json)

        with riseup_vpn_configurator.gateway_json.open() as f:
            j = json.load(f)
        assert list(j.keys()) == ['gateways', 'locations', 'openvpn_configuration', 'serial', 'version']
        assert list(j['gateways'][0].keys()) == ['capabilities', 'host', 'ip_address', 'location']

    def test_update_vpn_ca_certificate(self, caplog):
        from riseup_vpn_configurator import update_vpn_ca_certificate
        caplog.set_level(logging.INFO)

        update_vpn_ca_certificate()

        assert riseup_vpn_configurator.ca_cert_file.exists()
        assert "Sucessfully saved VPN CA" in caplog.text
        assert self.check_permissions_of_file(riseup_vpn_configurator.ca_cert_file)

        ca_cert_file = riseup_vpn_configurator.ca_cert_file.read_text()
        assert ca_cert_file.startswith("-----BEGIN CERTIFICATE-----")
        assert ca_cert_file.strip().endswith("-----END CERTIFICATE-----")

    def test_update_vpn_client_credentials(self, caplog):
        from riseup_vpn_configurator import update_vpn_client_credentials, cache_api_ca_cert
        caplog.set_level(logging.INFO)

        cache_api_ca_cert()
        update_vpn_client_credentials()

        # BEGIN CHECK CERT
        assert riseup_vpn_configurator.cert_file.exists()
        assert "Sucessfully saved VPN client certificate" in caplog.text
        assert self.check_permissions_of_file(riseup_vpn_configurator.cert_file)

        ca_cert_file = riseup_vpn_configurator.cert_file.read_text()
        assert ca_cert_file.startswith("-----BEGIN CERTIFICATE-----")
        assert ca_cert_file.strip().endswith("-----END CERTIFICATE-----")
        # END CHECK CERT

        # BEGIN CHECK KEY
        assert riseup_vpn_configurator.key_file.exists()
        assert "Sucessfully saved VPN client key" in caplog.text
        assert self.check_permissions_of_file(riseup_vpn_configurator.key_file)

        key_file = riseup_vpn_configurator.key_file.read_text()
        assert key_file.startswith("-----BEGIN RSA PRIVATE KEY-----")
        assert key_file.strip().endswith("-----END RSA PRIVATE KEY-----")
        # END CHECK KEY

    def test_calc_latency(self):
        from riseup_vpn_configurator import calc_latency
        latency = calc_latency("1.1.1.1")
        assert type(latency) == float

    def test_list_gateways(self, capsys):
        from riseup_vpn_configurator import list_gateways, update_gateways

        update_gateways()
        list_gateways(False)
        captured = capsys.readouterr()
        assert "vpn01-sea.riseup.net location=Seattle       ip=204.13.164.252  protocols=tcp,udp ports=53,80,1194" in captured.out

    def test_list_gateways_with_benchmark(self, capsys):
        from riseup_vpn_configurator import list_gateways, update_gateways

        update_gateways()
        list_gateways(True)
        captured = capsys.readouterr()
        assert "vpn01-sea.riseup.net location=Seattle       ip=204.13.164.252  latency=" in captured.out
        assert "ms  protocols=tcp,udp ports=53,80,1194" in captured.out

    def test_generate_configurator_config(self):
        from riseup_vpn_configurator import sanity_checks
        with pytest.raises(SystemExit) as se:
            # sanity_checks() fails because it does not find our config file
            sanity_checks()
            assert se.value.code == 1

    def test_generate_vpn_configuration(self, capsys, caplog):
        from riseup_vpn_configurator import generate_configuration, update_gateways, update_vpn_client_credentials, update_vpn_ca_certificate, sanity_checks

        # BEGIN GENERATE CONFIG
        with pytest.raises(SystemExit):
            # sanity_checks() fails because it does not find our config file
            sanity_checks()
        captured = capsys.readouterr()
        riseup_vpn_configurator.config_file.write_text(captured.out)
        # END GENERATE CONFIG

        update_gateways()
        update_vpn_client_credentials()
        update_vpn_ca_certificate()
        caplog.set_level(logging.INFO)
        generate_configuration()
        assert "Sucessfully saved riseup.vpn " in caplog.text

        vpn_config = riseup_vpn_configurator.ovpn_file.read_text()
        assert "route 1.1.1.0 255.255.255.0 net_gateway" in vpn_config
        assert "proto udp" in vpn_config

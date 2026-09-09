from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "certificate-installer.sh"


def run(cmd: list[str], cwd: Path | None = None, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        input=input_text,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def bash(script: str, tmp_path: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "EASY_WAZUH_CERT_INSTALLER_TESTING": "yes",
        "BACKUP_ROOT": str(tmp_path / "backups"),
    }
    return subprocess.run(
        ["bash", "-c", f'source "{INSTALLER}"\n{script}'],
        cwd=ROOT,
        env=env,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def cert_config(path: Path, names: list[str], ips: list[str] | None = None) -> Path:
    alt_names = []
    for i, name in enumerate(names, start=1):
        alt_names.append(f"DNS.{i} = {name}")
    for i, ip in enumerate(ips or [], start=1):
        alt_names.append(f"IP.{i} = {ip}")
    path.write_text(
        textwrap.dedent(
            f"""
            [req]
            distinguished_name = dn
            x509_extensions = v3_req
            prompt = no
            [dn]
            CN = {names[0] if names else "wazuh.local"}
            [v3_req]
            subjectAltName = @alt_names
            [alt_names]
            {chr(10).join(alt_names)}
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def make_cert(tmp_path: Path, name: str, names: list[str], key_type: str = "rsa", ips: list[str] | None = None, encrypted: bool = False) -> tuple[Path, Path]:
    cert = tmp_path / f"{name}.crt"
    key = tmp_path / f"{name}.key"
    conf = cert_config(tmp_path / f"{name}.cnf", names, ips)
    if key_type == "ec":
        run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)])
        run(["openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(cert), "-days", "60", "-config", str(conf), "-extensions", "v3_req"])
    elif encrypted:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert), "-days", "60", "-config", str(conf), "-extensions", "v3_req", "-passout", "pass:secret"])
    else:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "60", "-config", str(conf), "-extensions", "v3_req"])
    return cert, key


def make_compose(tmp_path: Path, mode: str = "single-node") -> Path:
    stack = tmp_path / "wazuh-docker" / mode
    certs = stack / "config" / "wazuh_indexer_ssl_certs"
    certs.mkdir(parents=True)
    (certs / ".easy-wazuh-cert-endpoint").write_text("endpoint=wazuh.home.lan\n", encoding="utf-8")
    if mode == "multi-node":
        services = """
        services:
          wazuh-dashboard01.home.lan:
            image: wazuh/wazuh-dashboard:4.14.5
            ports:
              - "443:5601"
            volumes:
              - ./config/wazuh_indexer_ssl_certs/wazuh-dashboard01.home.lan.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
              - ./config/wazuh_indexer_ssl_certs/wazuh-dashboard01.home.lan-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem
              - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem
            environment:
              - WAZUH_API_URL=https://wazuh-manager01.home.lan:55000
          wazuh-manager01.home.lan:
            image: wazuh/wazuh-manager:4.14.5
            ports:
              - "55000:55000"
          wazuh-manager02.home.lan:
            image: wazuh/wazuh-manager:4.14.5
          wazuh-indexer01.home.lan:
            image: wazuh/wazuh-indexer:4.14.5
          nginx:
            image: nginx:stable
        """
    else:
        services = """
        services:
          wazuh.dashboard:
            image: wazuh/wazuh-dashboard:4.14.5
            ports:
              - "443:5601"
            volumes:
              - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
              - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem
              - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem
            environment:
              - WAZUH_API_URL=https://wazuh.manager:55000
          wazuh.manager:
            image: wazuh/wazuh-manager:4.14.5
            ports:
              - "55000:55000"
          wazuh.indexer:
            image: wazuh/wazuh-indexer:4.14.5
        """
    compose = stack / "docker-compose.yml"
    compose.write_text(textwrap.dedent(services), encoding="utf-8")
    return compose


def test_valid_rsa_certificate_bundle(tmp_path: Path):
    cert, key = make_cert(tmp_path, "rsa", ["wazuh.home.lan"])
    result = bash(f'validate_certificate_bundle "{cert}" "{key}" "" wazuh.home.lan', tmp_path)
    assert "Subject:" in result.stdout or "subject=" in result.stdout


def test_valid_ec_certificate_bundle(tmp_path: Path):
    cert, key = make_cert(tmp_path, "ec", ["wazuh.home.lan"], key_type="ec")
    bash(f'validate_certificate_bundle "{cert}" "{key}" "" wazuh.home.lan', tmp_path)


def test_wrong_private_key_is_rejected(tmp_path: Path):
    cert, _ = make_cert(tmp_path, "one", ["wazuh.home.lan"])
    _, other_key = make_cert(tmp_path, "two", ["wazuh.home.lan"])
    result = bash(f'validate_certificate_bundle "{cert}" "{other_key}" "" wazuh.home.lan', tmp_path, check=False)
    assert result.returncode != 0
    assert "do not match" in result.stderr


def test_wildcard_matches_single_label(tmp_path: Path):
    cert, key = make_cert(tmp_path, "wild", ["*.home.lan"])
    bash(f'validate_certificate_bundle "{cert}" "{key}" "" wazuh.home.lan wazuh-manager01.home.lan', tmp_path)


def test_bad_wildcard_is_rejected(tmp_path: Path):
    cert, key = make_cert(tmp_path, "wild", ["*.example.com"])
    result = bash(f'validate_certificate_bundle "{cert}" "{key}" "" wazuh.home.lan', tmp_path, check=False)
    assert result.returncode != 0
    assert "does not cover DNS SAN" in result.stderr


def test_missing_san_for_required_name_is_rejected(tmp_path: Path):
    cert, key = make_cert(tmp_path, "one", ["wazuh.home.lan"])
    result = bash(f'validate_certificate_bundle "{cert}" "{key}" "" wazuh-manager01.home.lan', tmp_path, check=False)
    assert result.returncode != 0
    assert "does not cover DNS SAN" in result.stderr


def test_ip_san_is_required_for_ip_endpoint(tmp_path: Path):
    cert, key = make_cert(tmp_path, "ip", ["wazuh.home.lan"], ips=["192.0.2.10"])
    bash(f'validate_certificate_bundle "{cert}" "{key}" "" 192.0.2.10', tmp_path)
    result = bash(f'validate_certificate_bundle "{cert}" "{key}" "" 192.0.2.11', tmp_path, check=False)
    assert result.returncode != 0
    assert "does not cover IP SAN" in result.stderr


def test_passphrase_protected_key_is_rejected(tmp_path: Path):
    cert, key = make_cert(tmp_path, "encrypted", ["wazuh.home.lan"], encrypted=True)
    result = bash(f'validate_certificate_bundle "{cert}" "{key}" "" wazuh.home.lan', tmp_path, check=False)
    assert result.returncode != 0
    assert "encrypted private keys are not supported" in result.stderr


def test_dashboard_discovery_targets_dashboard_service(tmp_path: Path):
    compose = make_compose(tmp_path)
    result = bash(f'discover_targets "{compose}"', tmp_path)
    assert "dashboard=wazuh.dashboard" in result.stdout
    assert "api=wazuh.manager" in result.stdout


def test_multi_node_identifies_exposed_api_manager_only(tmp_path: Path):
    compose = make_compose(tmp_path, "multi-node")
    result = bash(f'discover_targets "{compose}"', tmp_path)
    assert "dashboard=wazuh-dashboard01.home.lan" in result.stdout
    assert "api=wazuh-manager01.home.lan" in result.stdout
    assert "wazuh-manager02.home.lan" not in result.stdout


def test_dashboard_update_never_targets_root_ca(tmp_path: Path):
    compose = make_compose(tmp_path)
    script = f'''
      target="$(resolve_bind_source_for_target "{compose}" wazuh.dashboard /usr/share/wazuh-dashboard/certs/root-ca.pem)"
      [[ "$target" == *root-ca.pem ]]
    '''
    bash(script, tmp_path)
    text = INSTALLER.read_text(encoding="utf-8")
    assert "refusing to modify root-ca.pem" in text


def test_api_required_names_include_internal_dashboard_api_host(tmp_path: Path):
    compose = make_compose(tmp_path, "multi-node")
    result = bash(f'api_required_names "{compose}" wazuh-manager01.home.lan wazuh-dashboard01.home.lan', tmp_path)
    assert "wazuh.home.lan" in result.stdout
    assert "wazuh-manager01.home.lan" in result.stdout


def test_api_certificate_missing_internal_hostname_refuses_before_backup(tmp_path: Path):
    compose = make_compose(tmp_path, "multi-node")
    cert, key = make_cert(tmp_path, "public-only", ["wazuh.home.lan"])
    script = f'''
      served_certificate_fingerprint() {{ return 1; }}
      confirm() {{ echo "confirm should not be called"; return 1; }}
      create_backup_dir() {{ echo "backup should not be called"; return 1; }}
      install_api_certificate "{compose}" "{cert}" "{key}" ""
    '''
    result = bash(script, tmp_path, check=False)
    assert result.returncode != 0
    assert "does not cover all hostnames required" in result.stderr
    assert not (tmp_path / "backups").exists()


def test_backup_created_with_restrictive_permissions(tmp_path: Path):
    source = tmp_path / "old.key"
    source.write_text("PRIVATE", encoding="utf-8")
    source.chmod(0o644)
    result = bash(f'backup="$(create_backup_dir dashboard)"; backup_file_with_metadata "{source}" "$backup/dashboard" "private-key.pem"; stat -c "%a" "$backup"; stat -c "%a" "$backup/dashboard/private-key.pem"', tmp_path)
    assert result.stdout.splitlines() == ["700", "600"]


def test_idempotence_skips_restart(tmp_path: Path):
    compose = make_compose(tmp_path)
    cert, key = make_cert(tmp_path, "idem", ["wazuh.home.lan"])
    fp = run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"]).stdout.strip().split("=", 1)[1]
    script = f'''
      served_certificate_fingerprint() {{ echo "{fp}"; }}
      restart_target() {{ echo "restart should not happen"; return 1; }}
      install_dashboard_certificate "{compose}" "{cert}" "{key}" ""
    '''
    result = bash(script, tmp_path)
    assert "already installed" in result.stdout
    assert "restart should not happen" not in result.stdout


def test_restart_failure_rolls_dashboard_back(tmp_path: Path):
    compose = make_compose(tmp_path)
    certs = compose.parent / "config" / "wazuh_indexer_ssl_certs"
    current_cert, current_key = make_cert(tmp_path, "current", ["wazuh.home.lan"])
    target_cert = certs / "wazuh.dashboard.pem"
    target_key = certs / "wazuh.dashboard-key.pem"
    target_cert.write_text(current_cert.read_text(encoding="utf-8"), encoding="utf-8")
    target_key.write_text(current_key.read_text(encoding="utf-8"), encoding="utf-8")
    (certs / "root-ca.pem").write_text("ROOT", encoding="utf-8")
    new_cert, new_key = make_cert(tmp_path, "new", ["wazuh.home.lan"])
    old = target_cert.read_text(encoding="utf-8")
    script = f'''
      served_certificate_fingerprint() {{ return 1; }}
      confirm() {{ return 0; }}
      restart_target() {{ return 1; }}
      install_dashboard_certificate "{compose}" "{new_cert}" "{new_key}" "" || true
    '''
    bash(script, tmp_path)
    assert target_cert.read_text(encoding="utf-8") == old
    assert (certs / "root-ca.pem").read_text(encoding="utf-8") == "ROOT"


def test_tls_failure_rolls_dashboard_back(tmp_path: Path):
    compose = make_compose(tmp_path)
    certs = compose.parent / "config" / "wazuh_indexer_ssl_certs"
    current_cert, current_key = make_cert(tmp_path, "current", ["wazuh.home.lan"])
    target_cert = certs / "wazuh.dashboard.pem"
    target_key = certs / "wazuh.dashboard-key.pem"
    target_cert.write_text(current_cert.read_text(encoding="utf-8"), encoding="utf-8")
    target_key.write_text(current_key.read_text(encoding="utf-8"), encoding="utf-8")
    (certs / "root-ca.pem").write_text("ROOT", encoding="utf-8")
    new_cert, new_key = make_cert(tmp_path, "new", ["wazuh.home.lan"])
    script = f'''
      served_certificate_fingerprint() {{ return 1; }}
      confirm() {{ return 0; }}
      restart_target() {{ return 0; }}
      service_running() {{ return 0; }}
      verify_endpoint_tls() {{ return 1; }}
      install_dashboard_certificate "{compose}" "{new_cert}" "{new_key}" "" || true
    '''
    bash(script, tmp_path)
    assert target_cert.read_text(encoding="utf-8") == current_cert.read_text(encoding="utf-8")


def test_restore_dashboard_backup(tmp_path: Path):
    compose = make_compose(tmp_path)
    target_cert = compose.parent / "config" / "wazuh_indexer_ssl_certs" / "wazuh.dashboard.pem"
    target_key = compose.parent / "config" / "wazuh_indexer_ssl_certs" / "wazuh.dashboard-key.pem"
    target_cert.write_text("NEWCERT", encoding="utf-8")
    target_key.write_text("NEWKEY", encoding="utf-8")
    backup = tmp_path / "backup"
    (backup / "dashboard").mkdir(parents=True)
    (backup / "metadata").mkdir()
    (backup / "dashboard" / "certificate.pem").write_text("OLDCERT", encoding="utf-8")
    (backup / "dashboard" / "private-key.pem").write_text("OLDKEY", encoding="utf-8")
    (backup / "metadata" / "dashboard.env").write_text(f"certificate_target={target_cert}\nprivate_key_target={target_key}\nservice=wazuh.dashboard\n", encoding="utf-8")
    bash(f'restore_dashboard_files "{backup}"', tmp_path)
    assert target_cert.read_text(encoding="utf-8") == "OLDCERT"
    assert target_key.read_text(encoding="utf-8") == "OLDKEY"


def test_static_security_guards():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "set -Eeuo pipefail" in text
    assert "docker compose down" not in text
    assert "down -v" not in text
    assert "docker volume prune" not in text
    assert "docker system prune --volumes" not in text
    assert "curl -k" not in text
    assert "verify=False" not in text
    assert "eval " not in text
    assert "chmod 777" not in text
    assert "chmod 666" not in text
    assert "root-ca.pem" in text
    assert "refusing to modify root-ca.pem" in text



def make_expired_cert(tmp_path: Path) -> tuple[Path, Path]:
    ca_key = tmp_path / "ca.key"
    ca_cert = tmp_path / "ca.crt"
    leaf_key = tmp_path / "expired.key"
    csr = tmp_path / "expired.csr"
    cert = tmp_path / "expired.crt"
    conf = cert_config(tmp_path / "expired.cnf", ["wazuh.home.lan"])
    ca_dir = tmp_path / "ca"
    (ca_dir / "certs").mkdir(parents=True)
    (ca_dir / "newcerts").mkdir()
    (ca_dir / "index.txt").write_text("", encoding="utf-8")
    (ca_dir / "serial").write_text("1000\n", encoding="utf-8")
    ca_conf = ca_dir / "openssl.cnf"
    ca_conf.write_text(
        textwrap.dedent(
            f"""
            [ca]
            default_ca = CA_default
            [CA_default]
            dir = {ca_dir}
            database = $dir/index.txt
            new_certs_dir = $dir/newcerts
            certificate = {ca_cert}
            private_key = {ca_key}
            serial = $dir/serial
            default_md = sha256
            policy = policy_any
            x509_extensions = v3_req
            copy_extensions = copy
            [policy_any]
            commonName = supplied
            [v3_req]
            subjectAltName = DNS:wazuh.home.lan
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "365", "-subj", "/CN=Test CA"])
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(leaf_key), "-out", str(csr), "-config", str(conf)])
    run(["openssl", "ca", "-batch", "-config", str(ca_conf), "-startdate", "20200101000000Z", "-enddate", "20200102000000Z", "-in", str(csr), "-out", str(cert)])
    return cert, leaf_key


def test_expired_certificate_is_rejected(tmp_path: Path):
    cert, key = make_expired_cert(tmp_path)
    result = bash(f'validate_certificate_bundle "{cert}" "{key}" "" wazuh.home.lan', tmp_path, check=False)
    assert result.returncode != 0
    assert "certificate is expired" in result.stderr


def test_unsupported_dashboard_tls_terminator_is_rejected(tmp_path: Path):
    compose = make_compose(tmp_path)
    content = compose.read_text(encoding="utf-8").replace("wazuh/wazuh-dashboard:4.14.5", "nginx:stable")
    compose.write_text(content, encoding="utf-8")
    result = bash(f'discover_targets "{compose}"', tmp_path, check=False)
    assert result.returncode != 0
    assert "This topology is not supported in V1" in result.stderr


def test_same_certificate_preflight_refuses_before_dashboard_install(tmp_path: Path):
    compose = make_compose(tmp_path, "multi-node")
    cert, key = make_cert(tmp_path, "public-only", ["wazuh.home.lan"])
    script = f"""
      prompt_certificate_inputs() {{ CERT_INPUT="{cert}"; KEY_INPUT="{key}"; CHAIN_INPUT=""; }}
      install_dashboard_certificate() {{ echo "dashboard install should not happen"; return 1; }}
      install_api_certificate() {{ echo "api install should not happen"; return 1; }}
      install_same_certificate "{compose}"
    """
    result = bash(script, tmp_path, check=False)
    assert result.returncode != 0
    assert "dashboard install should not happen" not in result.stdout


def test_static_no_internal_pki_or_filebeat_targets():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "wazuh-indexer" not in text
    assert "filebeat" not in text.lower()
    assert "docker compose down" not in text
    assert "docker volume" not in text


def test_served_certificate_uses_local_connect_host_with_public_sni(tmp_path: Path):
    script = '''
      make_tmp_dir
      timeout() {
        shift
        printf '%s\n' "$*" > "$TMP_DIR/openssl-command.txt"
        printf '%s\n' '-----BEGIN CERTIFICATE-----' 'MIIB' '-----END CERTIFICATE-----'
      }
      certificate_fingerprint() { cat "$TMP_DIR/openssl-command.txt"; }
      served_certificate_fingerprint wazuh.home.lan 443
    '''
    result = bash(script, tmp_path)
    assert "-connect 127.0.0.1:443" in result.stdout
    assert "-servername wazuh.home.lan" in result.stdout

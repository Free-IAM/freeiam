# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0

import contextlib
import datetime
import io
import logging
import shutil
import sys
import tempfile
import time
from pathlib import Path

import docker
import ldap
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from testcontainers.core.container import DockerContainer


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

BASE_DN = 'dc=freeiam,dc=org'
ADMIN_DN = f'cn=admin,{BASE_DN}'
ADMIN_PW = 'iamfree'
CONFIG_DN = 'cn=config'
CONFIG_ADMIN_DN = 'cn=admin,cn=config'
CONFIG_ADMIN_PW = 'really'
ORGANISATION = 'FreeIAM Org'
DOMAIN = 'freeiam.org'

container = None
last_log = {0: '', 1: ''}
client = docker.from_env()


def pytest_sessionstart(session):
    fmt = session.config.getini('log_format')
    for handler in logging.getLogger().handlers:
        handler.setFormatter(ExtraFormatter(fmt + ' %(extras)s'))


def pytest_addoption(parser):
    parser.addoption(
        '--no-wait-tls',
        action='store_true',
        default=False,
        help='Do not wait for LDAP SSL readiness before running SSL tests',
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    result = outcome.get_result()
    if not container:
        return
    if result.failed:
        if result.when != 'call':
            log.error('FAILURE during %s', result.when)
        dump_logs(container, level=logging.ERROR)
    else:
        last_log.update({i: log.decode('UTF-8', 'replace') for i, log in enumerate(container.get_logs())})


class ExtraFormatter(logging.Formatter):
    def format(self, record):
        standard_attrs = logging.LogRecord('', '', '', '', '', '', '', '').__dict__.keys()
        extras = {k: v for k, v in record.__dict__.items() if k not in standard_attrs}
        extras_str = ' '.join(f'{k}={v!r}' for k, v in extras.items())
        record.extras = extras_str
        return super().format(record)


def wait_for_ldap(ldap_uri, binddn, bindpw, count=10):
    log.info('Connecting to %s', ldap_uri)
    for _ in range(count):
        try:
            print('.', end='')
            sys.stdout.buffer.flush()
            conn = ldap.initialize(ldap_uri)
            conn.simple_bind_s(binddn, bindpw)
            conn.unbind_s()
            break
        except ldap.INVALID_CREDENTIALS:
            time.sleep(0.5)  # set up sometimes takes some time to create initial users
        except ldap.SERVER_DOWN:
            time.sleep(1)
    else:
        print()
        return False
    print()
    return True


def wait_for_ldaps(ldaps_uri, ca_cert, admin_dn, admin_pw):
    start = time.time()
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_cert)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    log.info('Connecting to %s with %s', ldaps_uri, ca_cert)
    for _ in range(120):
        try:
            print('.', end='')
            sys.stdout.buffer.flush()
            conn = ldap.initialize(ldaps_uri)
            conn.simple_bind_s(admin_dn, admin_pw)
            conn.unbind_s()
            break
        except ldap.SERVER_DOWN:
            time.sleep(1)
    else:
        print()
        return False
    print()
    log.info('Took %s seconds', (time.time() - start))
    return True


def enable_config(ldap_uri):
    return
    conn = ldap.initialize(ldap_uri)
    conn.simple_bind_s(CONFIG_ADMIN_DN, CONFIG_ADMIN_PW)

    try:
        with contextlib.suppress(ldap.ALREADY_EXISTS, ldap.CONSTRAINT_VIOLATION):
            conn.modify_s(CONFIG_DN, [(ldap.MOD_ADD, 'olcAllows', b'pagedResults')])
    finally:
        conn.unbind_s()


def dump_logs(container, file=None, level=logging.INFO):
    if not container:
        return
    current_log = container.get_logs()
    log_it = file is None
    file = io.StringIO() if log_it else file
    print('\n################################### LOGS', file=file)
    for i, _entry in enumerate(current_log):
        entry = _entry.decode('UTF-8', 'replace')
        additions = entry.removeprefix(last_log.get(i, ''))
        if additions:
            print(additions, file=file)
        else:
            print('No further logs since last time', i, file=file)
        last_log[i] = entry
    print('################################### END', file=file)
    if log_it:
        log.log(level, '%s', file.getvalue())


# FIXME: @pytest.fixture(autouse=True)
def wait_for_ssl_if_marked(request, ldap_server):
    if 'tls' not in request.keywords or request.config.getoption('--no-wait-tls'):
        return
    if not wait_for_ldaps(ldap_server['ldaps_uri'], ldap_server['ca_cert'], ldap_server['bind_dn'], ldap_server['bind_pw']):
        pytest.fail('LDAP TLS setup start failed')


def get_exposed_port(container, container_port: int, ipv4: bool = True) -> int:
    """
    Return the host-mapped port for a given container port.
    Works with dual-stack (IPv4 + IPv6) bindings.
    """
    client = docker.from_env()
    cid = container._container.id
    info = client.api.inspect_container(cid)
    port_bindings = info['NetworkSettings']['Ports']

    key = f'{container_port}/tcp'
    if key not in port_bindings or not port_bindings[key]:
        msg = f'Container port {container_port} not exposed'
        raise RuntimeError(msg)

    for binding in port_bindings[key]:
        if ipv4 and binding['HostIp'] == '0.0.0.0':  # noqa: S104
            return int(binding['HostPort'])
        if not ipv4 and binding['HostIp'] == '::':
            return int(binding['HostPort'])

    msg = f'No binding found for container port {container_port}'
    raise RuntimeError(msg)


@pytest.fixture(scope='session')
def ldap_server():
    with _ldap_server() as s:
        yield s


@contextlib.contextmanager
def _ldap_server():  # noqa: PLR0915,PLR0914
    global container  # noqa: PLW0603
    for logname in ('docker.utils.config', 'docker.auth', 'urllib3.connectionpool'):
        logging.getLogger(logname).setLevel(logging.WARNING)

    cert_dir = Path(tempfile.mkdtemp())
    if not (Path.cwd() / 'tests' / 'certs').exists():
        ca_cert, ca_key, ca_path = generate_ca(cert_dir, f'{ORGANISATION} CA')
        generate_signed_cert(cert_dir, ca_cert, ca_key, cn=DOMAIN, filename_prefix='ldap')
    else:
        shutil.copytree(str(Path.cwd() / 'tests' / 'certs'), str(cert_dir), dirs_exist_ok=True)
        ca_path = cert_dir / 'ca.crt'

    cert_dir_copy = cert_dir.with_suffix('.copy')
    shutil.copytree(cert_dir, cert_dir_copy)
    # 'HostConfig': {
    #     'Sysctls': {
    #         'net.ipv6.conf.all.disable_ipv6': '1',
    #         'net.ipv6.conf.default.disable_ipv6': '1',
    #         'net.ipv6.conf.lo.disable_ipv6': '1',
    #     }
    # }

    container_ = (
        DockerContainer('bitnamilegacy/openldap:2.6')
        .with_exposed_ports(1389, 1636)
        .with_env('LDAP_ORGANISATION', ORGANISATION)
        .with_env('LDAP_PORT_NUMBER', '1389')
        .with_env('LDAP_LDAPS_PORT_NUMBER', '1636')
        .with_env('LDAP_ROOT', BASE_DN)
        .with_env('LDAP_ADMIN_PASSWORD', ADMIN_PW)
        .with_env('LDAP_CONFIG_ADMIN_ENABLED', 'yes')
        .with_env('LDAP_CONFIG_PASSWORD', CONFIG_ADMIN_PW)
        .with_env('LDAP_PASSWORDS', 'iamfree1,iamfree2')
        # 1      (0x1 trace) trace function calls
        # 2      (0x2 packets) debug packet handling
        # 4      (0x4 args) heavy trace debugging (function args)
        # 8      (0x8 conns) connection management
        # 16     (0x10 BER) print out packets sent and received
        # 32     (0x20 filter) search filter processing
        # 64     (0x40 config) configuration file processing
        # 128    (0x80 ACL) access control list processing
        # 256    (0x100 stats) connections, LDAP operations, results (recommended)
        # 512    (0x200 stats2) stats2 log entries sent
        # 1024   (0x400 shell) print communication with shell backends
        # 2048   (0x800 parse) entry parsing
        # 16384  (0x4000 sync) LDAPSync replication
        # 32768  (0x8000 none) only messages that get logged whatever log level is set
        # .with_env('LDAP_LOGLEVEL', str(0x1 | 0x4 | 0x100 | 0x200))  # stats stats2 args trace
        .with_env('LDAP_LOGLEVEL', '256')
        .with_env('LDAP_PASSWORD_HASH', '{CRYPT}')
        .with_env('LDAP_CONFIGURE_PPOLICY', 'yes')
        .with_env('LDAP_ENABLE_TLS', 'yes')
        .with_env('LDAP_TLS_CERT_FILE', '/opt/bitnami/openldap/certs/ldap.crt')
        .with_env('LDAP_TLS_KEY_FILE', '/opt/bitnami/openldap/certs/ldap.key')
        .with_env('LDAP_TLS_CA_FILE', '/opt/bitnami/openldap/certs/ca.crt')
        .with_env('LDAP_TLS_DH_PARAMS_FILE', '/opt/bitnami/openldap/certs/dhparam.pem')
        .with_env('LDAP_TLS_VERIFY_CLIENT', 'never')
        .with_volume_mapping(str(cert_dir_copy), '/opt/bitnami/openldap/certs', mode='rw')
        .with_volume_mapping(str(Path.cwd() / 'tests/ldifs/'), '/ldifs/', mode='ro')
        .with_volume_mapping(str(Path.cwd() / 'tests/entrypoint/'), '/docker-entrypoint-initdb.d/', mode='ro')
    )
    container_.start()
    container = container_

    def stop():
        # client.networks.create(net_name, driver='bridge')
        # client.networks.get(net_name).disconnect(container._container.id, force=True)
        cn = client.containers.get(container._container.id)
        cn.stop()

    def start():
        # client.networks.get(net_name).connect(container._container.id)
        # client.networks.get(net_name).remove()
        cn = client.containers.get(container._container.id)
        cn.start()

    try:
        host = container.get_container_host_ip()
        port_ldap = int(container.get_exposed_port(1389))
        port_ldaps_ip4 = int(get_exposed_port(container, 1636, ipv4=True))
        port_ldaps = int(get_exposed_port(container, 1636, ipv4=False))
        ldap_uri = f'ldap://localhost:{port_ldap}/'
        ldaps_uri = f'ldaps://localhost:{port_ldaps}/'
        ldaps_uri_ip4 = f'ldaps://localhost:{port_ldaps_ip4}/'
        ca_cert = str(ca_path)
        printl = log.info
        printl(f'openssl x509 -in {ca_cert} -text -noout')
        printl(f'openssl s_client -starttls ldap -connect localhost:{port_ldap}')
        printl(f'openssl s_client -connect localhost:{port_ldaps} -showcerts')
        env_vars = f'LDAPTLS_REQCERT=allow LDAPTLS_CACERT="{ca_cert}"'
        printl(f'{env_vars} ldapsearch -LLL -H "{ldap_uri}"  -D "{ADMIN_DN}" -w "{ADMIN_PW}" -b "{BASE_DN}"')
        printl(f'{env_vars} ldapsearch -LLL -H "{ldap_uri}"  -D "{ADMIN_DN}" -w "{ADMIN_PW}" -b "{BASE_DN}" -ZZ')
        printl(f'{env_vars} ldapsearch -LLL -H "{ldaps_uri}" -D "{ADMIN_DN}" -w "{ADMIN_PW}" -b "{BASE_DN}"')

        if not wait_for_ldap(ldap_uri, ADMIN_DN, ADMIN_PW):
            dump_logs(container)
            pytest.fail('LDAP Server start failed')

        if not wait_for_ldap(ldaps_uri, ADMIN_DN, ADMIN_PW):
            # since OL 2.6: 0.0.0.0:32898->1389/tcp, :::32897->1389/tcp, 0.0.0.0:32897->1636/tcp, :::32896->1636/tcp
            # try the port from the other IP interface
            port_ldaps = port_ldaps_ip4
            ldaps_uri = ldaps_uri_ip4
            print(f'Wrong ldaps port: trying {port_ldaps} {ldaps_uri}')

        enable_config(ldap_uri)

        yield {
            'container': container,
            'client': client,
            'start': start,
            'stop': stop,
            'host': host,
            'port_ldap': port_ldap,
            'port_ldaps': port_ldaps,
            'ca_cert': ca_cert,
            'base_dn': BASE_DN,
            'bind_dn': ADMIN_DN,
            'bind_pw': ADMIN_PW,
            'ldap_uri': ldap_uri,
            'ldaps_uri': ldaps_uri,
        }
    except Exception:
        dump_logs(container)
        raise
    finally:
        # breakpoint()
        container.stop()
        container = None
        shutil.rmtree(cert_dir)


@pytest.fixture(scope='session')
def base_dn():
    return BASE_DN


@pytest.fixture(scope='session')
def ldap_uri(ldap_server):
    return ldap_server['ldap_uri']


@pytest.fixture(scope='session')
def ldaps_uri(ldap_server):
    return ldap_server['ldaps_uri']


def generate_ca(cert_dir: Path, cn):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path = cert_dir / 'ca.crt'
    ca_key_path = cert_dir / 'ca.key'

    ca_cert_path.write_bytes(ca_cert.public_bytes(Encoding.PEM))
    ca_key_path.write_bytes(ca_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    parameters = dh.generate_parameters(generator=2, key_size=2048)
    (cert_dir / 'dhparam.pem').write_bytes(
        parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)
    )

    return ca_cert, ca_key, ca_cert_path


def generate_signed_cert(cert_dir: Path, ca_cert, ca_key, cn: str, filename_prefix: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_path = cert_dir / f'{filename_prefix}.crt'
    key_path = cert_dir / f'{filename_prefix}.key'

    cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
    key_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    return cert_path, key_path

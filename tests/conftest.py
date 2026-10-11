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
last_log = b''
LDAP_LABEL = 'org.freeiam.role'
LDAP_LABEL_VALUE = 'test-ldap'
CERT_MOUNT = '/opt/bitnami/openldap/certs'
LDAP_IMAGE = 'bitnamilegacy/openldap:2.6'
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
    group = parser.getgroup('ldap')
    group.addoption(
        '--reuse-ldap',
        nargs='?',
        const='auto',
        default=None,
        metavar='CONTAINER',
        help='Reuse a running LDAP container (auto-discover or specify name/ID)',
    )
    group.addoption('--keep-ldap', action='store_true', default=False, help='Create a persistent LDAP container and leave it running')


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
        remember_logs(container)


class ExtraFormatter(logging.Formatter):
    def format(self, record):
        standard_attrs = logging.LogRecord('', logging.DEBUG, '', 0, '', (), None, '').__dict__.keys()
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


def remember_logs(cn):
    global last_log  # noqa: PLW0603
    last_log = cn.logs(stdout=True, stderr=True)


def dump_logs(cn, file: io.StringIO | None = None, level=logging.INFO):
    global last_log  # noqa: PLW0603
    if cn is None:
        return
    current = cn.logs(stdout=True, stderr=True)
    additions = current.removeprefix(last_log)
    last_log = current
    out = file if file is not None else io.StringIO()
    print('\n################################### LOGS', file=out)
    print(additions.decode('UTF-8', 'replace') if additions else 'No further logs since last time', file=out)
    print('################################### END', file=out)
    if file is None:
        log.log(level, '%s', out.getvalue())


# FIXME: @pytest.fixture(autouse=True)
def wait_for_ssl_if_marked(request, ldap_server):
    if 'tls' not in request.keywords or request.config.getoption('--no-wait-tls'):
        return
    if not wait_for_ldaps(ldap_server['ldaps_uri'], ldap_server['ca_cert'], ldap_server['bind_dn'], ldap_server['bind_pw']):
        pytest.fail('LDAP TLS setup start failed')


def get_exposed_port(cn, container_port: int, ipv4: bool = True) -> int:
    """Inspect docker-py container port bindings, preferring requested IP family."""
    cn.reload()
    bindings = cn.attrs['NetworkSettings']['Ports'].get(f'{container_port}/tcp') or []
    preferred = ('0.0.0.0', '127.0.0.1', '') if ipv4 else ('::', '::1')  # noqa: S104
    for host_ip in preferred:
        for binding in bindings:
            if binding['HostIp'] == host_ip:
                return int(binding['HostPort'])
    if bindings:
        return int(bindings[0]['HostPort'])
    msg = f'Container port {container_port} is not published'
    raise RuntimeError(msg)


@pytest.fixture(scope='session')
def ldap_server(request):
    reuse = request.config.getoption('--reuse-ldap')
    keep = request.config.getoption('--keep-ldap')
    if reuse is not None and keep:
        pytest.fail('--reuse-ldap and --keep-ldap are mutually exclusive', pytrace=False)
    with _ldap_server(reuse=reuse, keep=keep) as server:
        yield server


@contextlib.contextmanager
def _ldap_server(reuse=None, keep=False):  # noqa: PLR0915
    global container, last_log  # noqa: PLW0603
    for logname in ('docker.utils.config', 'docker.auth', 'urllib3.connectionpool'):
        logging.getLogger(logname).setLevel(logging.WARNING)

    cert_dir = None
    owned = False
    persistent = False
    cn = discover_container(reuse)
    try:
        if cn is None:
            persistent = keep
            owned = True
            cert_dir = Path.cwd() / '.pytest_cache' / 'freeiam-ldap-certs' if keep else Path(tempfile.mkdtemp(prefix='freeiam-ldap-certs-'))
            create_certs(cert_dir)
            cn = create_container(cert_dir, persistent=keep)
            log.info('Started LDAP container %s (persistent=%s)', cn.id[:12], persistent)

        container = cn
        last_log = b''
        ca_cert = ca_from_mounts(cn)
        port_ldap = get_exposed_port(cn, 1389)
        port_ldaps = get_exposed_port(cn, 1636)
        # Published port bindings are on the Docker host, as in the original fixture.
        host = 'localhost'
        ldap_uri = f'ldap://{host}:{port_ldap}/'
        ldaps_uri = f'ldaps://{host}:{port_ldaps}/'
        log.info('LDAP container: %s, CA: %s', cn.id[:12], ca_cert)
        log.info('openssl x509 -in %s -text -noout', ca_cert)
        log.info('openssl s_client -starttls ldap -connect %s:%s', host, port_ldap)
        log.info('openssl s_client -connect %s:%s -showcerts', host, port_ldaps)
        env_vars = f'LDAPTLS_REQCERT=allow LDAPTLS_CACERT="{ca_cert}"'
        for uri, extra in ((ldap_uri, ''), (ldap_uri, '-ZZ'), (ldaps_uri, '')):
            log.info('%s ldapsearch -LLL -H "%s" -D "%s" -w "%s" -b "%s" %s', env_vars, uri, ADMIN_DN, ADMIN_PW, BASE_DN, extra)

        if not wait_for_ldap(ldap_uri, ADMIN_DN, ADMIN_PW):
            dump_logs(cn)
            pytest.fail('LDAP Server start failed: No connection possible.')
        if not wait_for_ldaps(ldaps_uri, ca_cert, ADMIN_DN, ADMIN_PW):
            dump_logs(cn)
            pytest.fail('LDAP TLS Server start failed: No connection possible.')
        enable_config(ldap_uri)
        remember_logs(cn)

        def stop():
            cn.stop()

        def start():
            cn.start()

        yield {
            'container': cn,
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
        dump_logs(cn)
        raise
    finally:
        if owned and not persistent and cn is not None:
            cn.stop()
        container = None
        last_log = b''
        if owned and not persistent and cert_dir is not None:
            shutil.rmtree(cert_dir)


def container_settings(cert_dir):
    environment = {
        'BITNAMI_DEBUG': 'true',
        'LDAP_ORGANISATION': ORGANISATION,
        'LDAP_PORT_NUMBER': '1389',
        'LDAP_LDAPS_PORT_NUMBER': '1636',
        'LDAP_ROOT': BASE_DN,
        'LDAP_ADMIN_PASSWORD': ADMIN_PW,
        'LDAP_CONFIG_ADMIN_ENABLED': 'yes',
        'LDAP_CONFIG_PASSWORD': CONFIG_ADMIN_PW,
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
        'LDAP_LOGLEVEL': '256',
        # 'LDAP_LOGLEVEL': str(0x1 | 0x4 | 0x16 | 0x100 | 0x200),  # trace args BER stats stats2
        'LDAP_PASSWORD_HASH': '{CRYPT}',
        'LDAP_CONFIGURE_PPOLICY': 'yes',
        'LDAP_ENABLE_TLS': 'yes',
        'LDAP_TLS_CERT_FILE': f'{CERT_MOUNT}/ldap.crt',
        'LDAP_TLS_KEY_FILE': f'{CERT_MOUNT}/ldap.key',
        'LDAP_TLS_CA_FILE': f'{CERT_MOUNT}/ca.crt',
        'LDAP_TLS_DH_PARAMS_FILE': f'{CERT_MOUNT}/dhparam.pem',
        'LDAP_TLS_VERIFY_CLIENT': 'never',
    }
    mounts = {
        str(cert_dir): (CERT_MOUNT, 'rw'),
        str(Path.cwd() / 'tests/ldifs'): ('/ldifs', 'ro'),
        str(Path.cwd() / 'tests/entrypoint'): ('/docker-entrypoint-initdb.d', 'ro'),
        str(Path.cwd() / 'tests/entrypoint/noopsrch.so'): ('/opt/bitnami/openldap/lib/openldap/noopsrch.so', 'ro'),
        str(Path.cwd() / 'tests/entrypoint/usn.so'): ('/opt/bitnami/openldap/lib/openldap/usn.so', 'ro'),
    }
    return environment, mounts


def create_certs(directory):
    directory.mkdir(parents=True, exist_ok=True)
    source = Path.cwd() / 'tests' / 'certs'
    if source.is_dir():
        shutil.copytree(source, directory, dirs_exist_ok=True)
    elif not (directory / 'ca.crt').exists():
        ca, key, _ = generate_ca(directory, f'{ORGANISATION} CA')
        generate_signed_cert(directory, ca, key, cn=DOMAIN, filename_prefix='ldap')


def create_container(cert_dir, *, persistent):
    environment, mounts = container_settings(cert_dir)
    if persistent:
        # Use docker-py here: testcontainers' Ryuk may clean up even an un-stopped container.
        volumes = {src: {'bind': dst, 'mode': mode} for src, (dst, mode) in mounts.items()}
        return client.containers.run(
            LDAP_IMAGE,
            detach=True,
            ports={'1389/tcp': None, '1636/tcp': None},
            environment=environment,
            volumes=volumes,
            labels={LDAP_LABEL: LDAP_LABEL_VALUE},
            auto_remove=False,
        )
    tc = DockerContainer(LDAP_IMAGE, labels={LDAP_LABEL: LDAP_LABEL_VALUE}).with_exposed_ports(1389, 1636)
    tc.with_kwargs(auto_remove=True)
    for key, value in environment.items():
        tc.with_env(key, value)
    for src, (dst, mode) in mounts.items():
        tc.with_volume_mapping(src, dst, mode=mode)
    tc.start()
    return client.containers.get(tc._container.id)


def discover_container(selection):
    if selection is None:
        return None
    if selection != 'auto':
        try:
            cn = client.containers.get(selection)
        except docker.errors.NotFound:
            pytest.fail(f'LDAP container {selection!r} not found', pytrace=False)
        if cn.status != 'running':
            pytest.fail(f'LDAP container {selection!r} is not running', pytrace=False)
        return cn
    matches = client.containers.list(filters={'label': f'{LDAP_LABEL}={LDAP_LABEL_VALUE}'})
    if len(matches) != 1:
        pytest.fail(f'Expected exactly one running FreeIAM LDAP container; found {len(matches)}', pytrace=False)
    return matches[0]


def ca_from_mounts(cn):
    """Resolve the CA file through the container's bind-mount metadata."""
    cn.reload()
    ca_target = cn.attrs.get('Config', {}).get('Env', [])
    ca_target = next((v.split('=', 1)[1] for v in ca_target if v.startswith('LDAP_TLS_CA_FILE=')), f'{CERT_MOUNT}/ca.crt')
    for mount in cn.attrs.get('Mounts', []):
        destination = mount['Destination'].rstrip('/')
        if ca_target == destination or ca_target.startswith(destination + '/'):
            if mount['Type'] != 'bind':
                pytest.fail('LDAP CA mount is not a host bind mount; cannot resolve local CA file', pytrace=False)
            path = Path(mount['Source']) / ca_target.removeprefix(destination).lstrip('/')
            if not path.is_file():
                pytest.fail(f'LDAP CA certificate from Docker mount does not exist: {path}', pytrace=False)
            return str(path)
    pytest.fail(f'No Docker bind mount contains LDAP CA certificate {ca_target}', pytrace=False)


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
        x509
        .CertificateBuilder()
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
        x509
        .CertificateBuilder()
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

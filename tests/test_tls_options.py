from unittest.mock import call, patch

import pytest

from freeiam import ldap
from freeiam.ldap.constants import (
    TLSOption,
    TLSProtocol,
    TLSVerifyMode,
)


@pytest.fixture
def tls_files(tmp_path):
    files = {
        'ca_certfile': tmp_path / 'ca.pem',
        'certfile': tmp_path / 'client.pem',
        'keyfile': tmp_path / 'client.key',
        'crlfile': tmp_path / 'revocation.pem',
    }
    for path in files.values():
        path.write_text('test', encoding='ascii')

    files['ca_certdir'] = tmp_path / 'certs'
    files['ca_certdir'].mkdir()

    return {name: str(path) for name, path in files.items()}


@pytest.fixture(params=[ldap.Connection, ldap.sync_connection.Connection], scope='session')
def conn_class(request):
    return request.param


@pytest.mark.parametrize(
    'parameter, option, value',
    [
        ('require_cert', TLSOption.RequireCert, TLSVerifyMode.Never),
        ('require_san', TLSOption.RequireSAN, TLSVerifyMode.Try),
        ('minimum_protocol', TLSOption.ProtocolMin, TLSProtocol.TLS12),
        ('cipher_suite', TLSOption.CipherSuite, 'HIGH'),
    ],
)
def test_set_global_tls_options(parameter, option, value, conn_class):
    with patch.object(conn_class, 'set_global_option') as setter:
        conn_class.set_global_tls(**{parameter: value})

    assert call(option, value) in setter.call_args_list
    assert setter.call_args_list[-1] == call(TLSOption.NewContext, 0)


def test_set_global_tls_defaults(conn_class):
    with patch.object(conn_class, 'set_global_option') as setter:
        conn_class.set_global_tls()

    assert setter.call_args_list == [
        call(TLSOption.RequireCert, TLSVerifyMode.Demand),
        call(TLSOption.RequireSAN, TLSVerifyMode.Demand),
        call(TLSOption.ProtocolMin, TLSProtocol.TLS12),
        call(TLSOption.NewContext, 0),
    ]


@pytest.mark.parametrize(
    'parameter, option',
    [
        ('ca_certfile', TLSOption.CACertfile),
        ('ca_certdir', TLSOption.CACertdir),
        ('certfile', TLSOption.Certfile),
        ('keyfile', TLSOption.Keyfile),
        ('crlfile', TLSOption.CRLFile),
    ],
)
def test_set_global_tls_file_options(tls_files, parameter, option, conn_class):
    with patch.object(conn_class, 'set_global_option') as setter:
        conn_class.set_global_tls(
            **tls_files,
        )

    assert call(option, tls_files[parameter]) in setter.call_args_list


@pytest.mark.parametrize(
    'parameter, value',
    [
        ('certfile', 'cert.pem'),
        ('keyfile', 'key.pem'),
    ],
)
def test_set_global_tls_requires_cert_and_key(parameter, value, conn_class):
    with patch.object(conn_class, 'set_global_option') as setter, pytest.raises(ValueError, match=r'certfile.*keyfile'):
        conn_class.set_global_tls(**{parameter: value})

    setter.assert_not_called()


@pytest.mark.parametrize(
    'parameter',
    [
        'ca_certfile',
        'certfile',
        'keyfile',
        'crlfile',
        'ca_certdir',
    ],
)
def test_set_global_tls_invalid_paths(tmp_path, tls_files, parameter, conn_class):
    tls_files[parameter] = str(tmp_path / 'missing')

    with patch.object(conn_class, 'set_global_option') as setter, pytest.raises(OSError, match=parameter):
        conn_class.set_global_tls(**tls_files)

    setter.assert_not_called()


def test_set_global_tls_certdir_must_be_directory(tls_files, conn_class):
    tls_files['ca_certdir'] = tls_files['ca_certfile']

    with patch.object(conn_class, 'set_global_option') as setter, pytest.raises(OSError, match='ca_certdir'):
        conn_class.set_global_tls(**tls_files)

    setter.assert_not_called()


def test_set_global_tls_certfile_must_be_file(tls_files, conn_class):
    tls_files['certfile'] = tls_files['ca_certdir']

    with patch.object(conn_class, 'set_global_option') as setter, pytest.raises(OSError, match='certfile'):
        conn_class.set_global_tls(**tls_files)

    setter.assert_not_called()


def test_set_global_tls_applies_new_context_last(conn_class):
    with patch.object(conn_class, 'set_global_option') as setter:
        conn_class.set_global_tls(
            require_cert=TLSVerifyMode.Demand,
            require_san=TLSVerifyMode.Demand,
        )

    assert setter.call_args_list[-1] == call(TLSOption.NewContext, 0)
    assert setter.call_count > 1


def test_set_tls_delegates_to_global_implementation(conn_class):
    conn = conn_class('ldap://localhost:389')

    with patch.object(conn_class, 'set_global_tls') as setter:
        conn.set_tls(
            require_cert=TLSVerifyMode.Never,
            require_san=TLSVerifyMode.Never,
        )

    setter.assert_called_once()
    kwargs = setter.call_args.kwargs

    assert kwargs['_conn'] is conn
    assert kwargs['require_cert'] == TLSVerifyMode.Never
    assert kwargs['require_san'] == TLSVerifyMode.Never
    assert kwargs['minimum_protocol'] == TLSProtocol.TLS12


def test_set_tls_uses_connection_options(conn_class):
    conn = conn_class('ldap://localhost:389')

    with (
        patch.object(conn_class, 'set_option') as local_setter,
        patch.object(conn_class, 'set_global_option') as global_setter,
    ):
        conn.set_tls()

    assert local_setter.call_args_list == [
        call(TLSOption.RequireCert, TLSVerifyMode.Demand),
        call(TLSOption.RequireSAN, TLSVerifyMode.Demand),
        call(TLSOption.ProtocolMin, TLSProtocol.TLS12),
        call(TLSOption.NewContext, 0),
    ]
    global_setter.assert_not_called()


def test_set_global_tls_propagates_context_error(conn_class):
    with (
        patch.object(
            conn_class,
            'set_global_option',
            side_effect=lambda option, _value: (_ for _ in ()).throw(ValueError('TLS context failed')) if option == TLSOption.NewContext else None,
        ),
        pytest.raises(ValueError, match='TLS context failed'),
    ):
        conn_class.set_global_tls()

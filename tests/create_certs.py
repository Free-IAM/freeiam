# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0

import base64
import datetime as dt
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


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
        .not_valid_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(tz=dt.UTC) + dt.timedelta(days=365))
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
        .not_valid_before(dt.datetime.now(tz=dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(tz=dt.UTC) + dt.timedelta(days=365))
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


def base64url_uint(value: int) -> str:
    data = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def generate_jwks(output_file: Path, private_key_path: Path):
    if output_file.exists():
        return

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )
    public_numbers = private_key.public_key().public_numbers()

    jwks = {
        'keys': [
            {
                'kty': 'RSA',
                'kid': 'freeiam-test',
                'use': 'sig',
                'alg': 'RS256',
                'n': base64url_uint(public_numbers.n),
                'e': base64url_uint(public_numbers.e),
            }
        ]
    }

    jwk = jwks['keys'][0]

    thumbprint_data = json.dumps(
        {'e': jwk['e'], 'kty': jwk['kty'], 'n': jwk['n']},
        sort_keys=True,
        separators=(',', ':'),
    ).encode('ascii')

    jwk['kid'] = base64.urlsafe_b64encode(hashlib.sha256(thumbprint_data).digest()).rstrip(b'=').decode('ascii')

    output_file.write_text(json.dumps(jwks, indent=4) + '\n', encoding='utf-8')

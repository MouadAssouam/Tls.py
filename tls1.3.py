from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import os
from ipaddress import ip_address

# Directory to store certificates
CERT_DIR = "certs"

if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)

def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def generate_ca():
    # Generate CA key and certificate
    ca_key = generate_private_key()
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"ELK-CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # Save CA key
    with open(os.path.join(CERT_DIR, "ca.key.pem"), "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save CA certificate
    with open(os.path.join(CERT_DIR, "ca.cert.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("CA generated.")

def generate_certificate(common_name, sans=[], is_server=True):
    # Load CA key and cert
    with open(os.path.join(CERT_DIR, "ca.key.pem"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(os.path.join(CERT_DIR, "ca.cert.pem"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Generate key
    key = generate_private_key()

    # Build subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Build certificate
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(ca_cert.subject)
    cert_builder = cert_builder.public_key(key.public_key())
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(datetime.utcnow() - timedelta(days=1))
    cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=365))

    # Add extensions
    if is_server:
        extended_usages = [ExtendedKeyUsageOID.SERVER_AUTH]
    else:
        extended_usages = [ExtendedKeyUsageOID.CLIENT_AUTH]

    cert_builder = cert_builder.add_extension(
        x509.ExtendedKeyUsage(extended_usages),
        critical=False,
    )

    # Subject Alternative Names
    san_entries = []
    for name in sans:
        try:
            # If it's an IP address
            san_entries.append(x509.IPAddress(ip_address(name)))
        except ValueError:
            # If it's a DNS name
            san_entries.append(x509.DNSName(name))

    if san_entries:
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

    # Sign certificate
    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

    # Save key
    key_file = os.path.join(CERT_DIR, f"{common_name}.key.pem")
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save cert
    cert_file = os.path.join(CERT_DIR, f"{common_name}.cert.pem")
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificate for {common_name} generated.")

def main():
    generate_ca()

    # Define server and client certificates
    servers = {
        "elasticsearch": ["elasticsearch", "localhost", "127.0.0.1", "elasticsearch.nameofcompany.local"],
        "logstash": ["logstash", "localhost", "127.0.0.1", "logstash.nameofcompany.local"],
        "kibana": ["kibana", "localhost", "127.0.0.1", "kibana.nameofcompany.local"],
    }

    client = "client"  # Single client configuration

    # Generate server certificates
    for server, sans in servers.items():
        generate_certificate(server, sans=sans, is_server=True)

    # Generate client certificate
    generate_certificate(client, is_server=False)

if __name__ == "__main__":
    main()

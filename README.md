# Certificate Generator for Elasticsearch, Logstash, Kibana, and Client

This Python script generates SSL/TLS certificates for Elasticsearch, Logstash, Kibana, and a client. It includes functionality to generate a Certificate Authority (CA), server certificates with Subject Alternative Names (SANs), and client certificates signed by the CA.

## Features

- **Generate a Certificate Authority (CA)**: The script generates a self-signed CA certificate and its private key.
- **Generate Server Certificates**: For server applications like Elasticsearch, Logstash, and Kibana, the script generates certificates with SANs to support IP addresses and DNS names.
- **Generate Client Certificate**: A certificate for the client is generated, suitable for mutual authentication.
- **Custom SAN Entries**: Support for Subject Alternative Names, including IP addresses and DNS names.
- **RSA Key Generation**: The script uses RSA encryption with a 2048-bit key size.

## Requirements

- Python 3.6+
- `cryptography` library: Install it via pip:
  
  ```bash
  pip install cryptography
  ```

## Files Generated

- `ca.key.pem`: The private key for the Certificate Authority (CA).
- `ca.cert.pem`: The self-signed certificate for the Certificate Authority.
- `<common_name>.key.pem`: The private key for each generated certificate.
- `<common_name>.cert.pem`: The signed certificate for each server or client.

The certificates and keys are stored in a directory named `certs`.

## How to Use

1. **Install dependencies**:

   Make sure Python 3.6+ is installed and install the required libraries with pip:

   ```bash
   pip install cryptography
   ```

2. **Run the script**:

   Simply run the Python script to generate the certificates:

   ```bash
   python generate_certificates.py
   ```

   This will create a `certs` directory containing:
   - `ca.key.pem` and `ca.cert.pem` for the Certificate Authority.
   - Certificates for the servers (`elasticsearch.cert.pem`, `logstash.cert.pem`, `kibana.cert.pem`) and the client (`client.cert.pem`).
   - Private keys for the servers and client (`elasticsearch.key.pem`, `logstash.key.pem`, `kibana.key.pem`, `client.key.pem`).

3. **Using the certificates**:

   - The CA certificate (`ca.cert.pem`) can be used to verify server certificates.
   - The server certificates (`*.cert.pem`) and their corresponding private keys (`*.key.pem`) are used for securing server communications.
   - The client certificate (`client.cert.pem`) and its corresponding private key (`client.key.pem`) are used for client authentication in a secure system.

4. **Modify the server and client configuration**:

   The script is pre-configured with SANs for common IP addresses and domain names related to Elasticsearch, Logstash, and Kibana. You can modify the `servers` dictionary in the script to customize the names and SANs based on your needs.

## Example Directory Structure

After running the script, the directory will look something like this:

```
certs/
├── ca.cert.pem
├── ca.key.pem
├── client.cert.pem
├── client.key.pem
├── elasticsearch.cert.pem
├── elasticsearch.key.pem
├── kibana.cert.pem
├── kibana.key.pem
└── logstash.cert.pem
    └── logstash.key.pem
```

## Customization

- **Modify SANs**: You can add or modify the SANs (Subject Alternative Names) for each server or client by editing the `servers` dictionary in the `main()` function.
  
- **Change Expiry Time**: The certificates are set to expire in 1 year. You can change this by adjusting the `not_valid_after` parameter in the certificate generation.

- **Server/Client Roles**: The `is_server` flag differentiates between server and client certificates. Set it to `True` for server certificates and `False` for client certificates.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

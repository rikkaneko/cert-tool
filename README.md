# Certificate Tools (cert-tools)

A single bash script for managing internal PKI (Public Key Infrastructure) and self-signing certificates. This tool simplifies the creation and management of Root CAs, Intermediate CAs, and signed Server/Client certificates using OpenSSL.

## Features

- **Automated PKI hierarchy**: Easily create Root and Intermediate CAs.
- **Purpose-built certificates**: Generate certificates tailored for `server` (TLS) or `client` (mTLS) use.
- **Flexible configuration**: Use `cert.conf` for project-wide defaults or override via CLI flags.
- **Smart password management**: 
  - Root/Intermediate CAs are password-protected by default.
  - Server/Client certificates are unencrypted by default (ideal for automated services).
  - Explicit option for random password generation.
- **Certificate tracking**: Query and list existing certificates with expiration dates.
- **Renewal supporting**: Easily renew certificates while maintaining existing keys and CSRs.

## Prerequisites

- **OpenSSL**
- **Bash**

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd cert-tools
   ```

2. Make the script executable:
   ```bash
   chmod +x certs.sh
   ```

## Configuration

The script uses `cert.conf` for default settings. You can modify this file to set:
- `ASYM_ALGO`: Asymmetric algorithm (e.g., `ED25519`, `RSA`).
- `CIPHER`: Encryption cipher for private keys (e.g., `aes256`).
- `CA_DAYS` / `CERT_DAYS`: Validity periods.
- `OUTPUT_DIR`: Where certificates are stored.

## Usage

### Subcommands Overview

- `rootca`: Generate a new Root CA.
- `intermediate`: Create an Intermediate CA signed by a Root CA.
- `certs`: Issue Server or Client certificates.
- `info`: List and inspect certificates.
- `renew`: Renew an existing certificate.

---

### 1. Generate a Root CA

```bash
./certs.sh rootca --name "Example Root CA" --expiration 10y
```

**Example Output:**
```text
Generated random password at ./certs/Example_Root_CA/secret.txt
Generating Root CA: Example Root CA
Root CA created at ./certs/Example_Root_CA/certs.pem
```

### 2. Create an Intermediate CA

```bash
./certs.sh intermediate --ca "Example Root CA" --name "Example Intermediate CA"
```

**Example Output:**
```text
Generated random password at ./certs/Example_Intermediate_CA/secret.txt
Generating Intermediate CA: Example Intermediate CA signed by Example Root CA
Certificate request self-signature ok
subject=CN=Example Intermediate CA
Intermediate CA created at ./certs/Example_Intermediate_CA/certs.pem
```

### 3. Issue a Server Certificate

```bash
./certs.sh certs --ca "Example Intermediate CA" --name "server.example.com" --purpose server
```

**Example Output:**
```text
Generating server certificate: server.example.com signed by Example Intermediate CA
Certificate request self-signature ok
subject=CN=server.example.com
server certificate created at ./certs/server.example.com/certs.pem
```

### 4. Issue a Client Certificate

```bash
./certs.sh certs --ca "Example Intermediate CA" --name "user-client" --purpose client
```

**Example Output:**
```text
Generating client certificate: user-client signed by Example Intermediate CA
Certificate request self-signature ok
subject=CN=user-client
client certificate created at ./certs/user-client/certs.pem
```

### 5. View Certificate Info

List all certificates:
```bash
./certs.sh info
```

**Example Output:**
```text
Root/Intermediate CAs
Name                    | Expiration Date Time | Issuer
Example Root CA         | 2036-03-13T15:57:22Z | N/A
Example Intermediate CA | 2036-03-13T15:57:22Z | Example Root CA

Client Certificates
Name                    | Expiration Date Time | Issuer
server.example.com      | 2027-03-16T15:57:26Z | Example Intermediate CA
user-client             | 2027-03-16T15:57:22Z | Example Intermediate CA

Total: 4 certs
```

Inspect a specific certificate:
```bash
./certs.sh info "server.example.com"
```

### 6. Renew a Certificate

```bash
./certs.sh renew --name "server.example.com"
```

**Example Output:**
```text
Renewing certificate: server.example.com signed by Example Intermediate CA
Certificate request self-signature ok
subject=CN=server.example.com
Certificate renewed at ./certs/server.example.com/certs.pem
```

## Output Structure

Certificates are organized by their Common Name (CN) in the output directory:
```text
certs/
└── api.example.com/
    ├── certs.pem      # The certificate
    ├── privkey.pem    # The private key
    ├── fullchain.pem  # Certificate + CA Chain
    └── secret.txt     # Private key password (if applicable)
```

## License

This project is licensed under the LGPLv2.1.

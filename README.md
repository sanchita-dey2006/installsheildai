# InstallShield AI - Digital Signature Verification Module (Member 2)

Member 2's component of the **InstallShield AI** fake software installer detection system.

## Responsibilities

This module handles:
- **Publisher Verification**: Extracting and validating authentic publisher names from Windows Authenticode digital signatures.
- **Digital Certificate Validation**: Parsing certificate status (Valid, NotSigned, HashMismatch, NotTrusted, NotSupported, UnknownError).
- **Trusted Publisher Database**: Maintaining and querying a curated database of verified software vendors with boundary-aware entity matching to prevent publisher spoofing.
- **X.500 Distinguished Name Parsing**: Robust regex parsing for Common Name (`CN=...`) attributes in multi-field certificate subjects.
- **Security & Execution Isolation**: Running PowerShell signature checks using safe parameter blocks (`param([string]$Path)`) to eliminate command injection risks.
- **Performance & Caching**: Utilizing LRU caching for signature verification results and trusted publisher database disk access.

## Module Structure

```text
.
├── README.md
├── signature/
│   ├── __init__.py
│   ├── publisher.py
│   ├── verify_signature.py
│   └── trusted_publishers.json
└── analysis/
    ├── __init__.py
    ├── publisher.py
    ├── verify_signature.py
    ├── trusted_publishers.json
    ├── test_signature.py
    ├── test_publisher.py
    └── test_signature_verification.py
```

## Usage

```python
from signature.verify_signature import verify_signature
from signature.publisher import is_trusted_publisher

# Verify signature status and publisher
result = verify_signature("path/to/installer.exe")
print("Status:", result["status"])
print("Publisher:", result["publisher"])

# Check if publisher is trusted
trusted = is_trusted_publisher(result["publisher"])
print("Is Trusted:", trusted)
```

## Running Tests

```bash
python3 -m unittest analysis/test_signature_verification.py
```

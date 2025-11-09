# CryptionX - A Next-Gen Open Encryption Framework

[![PyPI version](https://badge.fury.io/py/cryptionx.svg)](https://badge.fury.io/py/cryptionx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/pypi/pyversions/cryptionx.svg)](https://pypi.org/project/cryptionx/)

**Simple, open, and transparent encryption for everyone.**

CryptionX is a modern, simple, and transparent encryption framework for Python. It is built with a clear goal: to provide real, understandable implementations of common cryptographic algorithms with **zero external dependencies**. All algorithms are implemented from scratch using only the Python standard library, making it a powerful tool for learning, prototyping, and situations where external dependencies are not an option.

---

## Key Features

-   ✅ **Zero External Dependencies**: Runs anywhere Python's standard library is available. Just `pip install cryptionx`.
-   🧩 **Modular & Pluggable Architecture**: Easily extend the framework by adding your own custom ciphers, hash algorithms, or key exchange protocols.
-   🔒 **Authenticated Encryption**: The built-in `AES-256-CTR` cipher uses an HMAC to provide Authenticated Encryption with Associated Data (AEAD), protecting against both eavesdropping and tampering.
-   🚀 **High-Level, Easy-to-Use API**: Simple methods for encrypting and decrypting strings, files, and even memory-efficient streams.
-   🔄 **Secure Key Exchange**: Includes a from-scratch implementation of the Diffie-Hellman (`DH-2048`) key exchange protocol for establishing shared secrets over an insecure channel.

---

## Security Disclaimer

CryptionX is designed for educational purposes and as a demonstration of cryptographic principles. While the algorithms are real implementations based on established standards, they **have not undergone a formal security audit**.

For production systems handling sensitive data, please use well-established, independently audited libraries like [`cryptography`](https://github.com/pyca/cryptography). **Do not use this library for mission-critical security applications without a thorough, independent security review.**

---

## Installation

CryptionX is available on PyPI. Install it using pip:

```bash
pip install cryptionx
```

---

## Quick Start

Encrypting and decrypting a message is simple and intuitive.

```
from cryptionx import CryptionX

# 1. Initialize the framework
cx = CryptionX()

# 2. Define your plaintext and a secure password
plaintext = "CryptionX: Real encryption with zero dependencies!"
password = "super_secure_password_123"

# 3. Encrypt the string
# The result is a JSON string containing metadata and the ciphertext
encrypted_data = cx.encrypt_string(plaintext, password, cipher="ChaCha20")

print(f"Encrypted: {encrypted_data[:100]}...")

# 4. Decrypt the string
decrypted_text = cx.decrypt_string(encrypted_data, password)

print(f"Decrypted: {decrypted_text}")
print(f"Success: {plaintext == decrypted_text}")

# --- Output ---
# Encrypted: {"metadata": {"cipher": "ChaCha20", "hash": "SHA256", "version": "1.0"}, "ciphertext": "a1vA8f1t11bV/...
# Decrypted: CryptionX: Real encryption with zero dependencies!
# Success: True
```

---

## Usage Examples
### 1. File Encryption and Decryption
CryptionX handles the reading and writing of files, packaging metadata and ciphertext into a single output file.

```
from cryptionx import CryptionX
import os

cx = CryptionX()
password = "a-different-secure-password"

# Create a dummy file to encrypt
with open("my_document.txt", "w") as f:
    f.write("This is a secret document that needs to be encrypted.")

# Encrypt the file
cx.encrypt_file(
    input_path="my_document.txt",
    output_path="my_document.encrypted",
    password=password,
    cipher="AES-256-CTR" # Using authenticated encryption
)
print("File 'my_document.txt' encrypted to 'my_document.encrypted'")

# Decrypt the file
cx.decrypt_file(
    input_path="my_document.encrypted",
    output_path="my_document.decrypted.txt",
    password=password
)
print("File 'my_document.encrypted' decrypted to 'my_document.decrypted.txt'")

# Verify the content
with open("my_document.decrypted.txt", "r") as f:
    content = f.read()
    print(f"Decrypted content matches original: {'secret document' in content}")

# Clean up created files
os.remove("my_document.txt")
os.remove("my_document.encrypted")
os.remove("my_document.decrypted.txt")
```

---

### 2. Stream Encryption (For Large Files)
For very large files, you can use the stream-based methods to encrypt data in chunks, keeping memory usage low.
```
from cryptionx import CryptionX
from io import BytesIO

cx = CryptionX()
password = "stream-password-!@#"

# Simulate a large file using BytesIO streams
original_data = b"This is some stream data that could be very large..." * 1000
input_stream = BytesIO(original_data)
encrypted_stream = BytesIO()

# Encrypt the stream
cx.encrypt_stream(input_stream, encrypted_stream, password, cipher="Salsa20")
print(f"Encrypted {len(original_data)} bytes of stream data.")

# Prepare for decryption by seeking to the beginning of the encrypted stream
encrypted_stream.seek(0)
decrypted_stream = BytesIO()

# Decrypt the stream
cx.decrypt_stream(encrypted_stream, decrypted_stream, password)

# Verify the result
decrypted_data = decrypted_stream.getvalue()
print(f"Decrypted {len(decrypted_data)} bytes.")
print(f"Stream integrity check passed: {original_data == decrypted_data}")
```

---

### 3. Diffie-Hellman Key Exchange
Establish a shared secret between two parties (e.g., Alice and Bob) over an insecure channel.
```
from cryptionx import CryptionX

cx = CryptionX()

# Get the Diffie-Hellman plugin
dh_plugin = cx.kx_plugins["DH-2048"]

# 1. Alice generates her key pair
alice_public_key, alice_private_key = dh_plugin.generate_keypair()

# 2. Bob generates his key pair
bob_public_key, bob_private_key = dh_plugin.generate_keypair()

# Alice and Bob exchange public keys...

# 3. Alice computes the shared secret using her private key and Bob's public key
alice_shared_secret = dh_plugin.derive_shared_secret(alice_private_key, bob_public_key)

# 4. Bob computes the shared secret using his private key and Alice's public key
bob_shared_secret = dh_plugin.derive_shared_secret(bob_private_key, alice_public_key)

print(f"Alice's derived secret: {alice_shared_secret.hex()}")
print(f"Bob's derived secret:   {bob_shared_secret.hex()}")
print(f"Secrets match: {alice_shared_secret == bob_shared_secret}")

# This shared secret can now be used as a key for symmetric encryption
```

---

### 4. Listing Available Algorithms
You can easily list all registered plugins.
```
from cryptionx import CryptionX

cx = CryptionX()
plugins = cx.list_plugins()

import json
print(json.dumps(plugins, indent=2))
```

---

**Output:**
```
{
  "hashes": [
    "SHA256",
    "SHA512",
    "BLAKE2b",
    "SHA3-256"
  ],
  "key_exchanges": [
    "DH-2048"
  ],
  "ciphers": [
    "ChaCha20",
    "Salsa20",
    "AES-256-CTR"
  ]
}
```

---

## Available Algorithms

### Encryption Algorithms

| Algorithm    | Type           | Implementation         | Notes                                                                 |
|---------------|----------------|-------------------------|----------------------------------------------------------------------|
| ChaCha20      | Stream Cipher  | From Scratch           | A fast, modern, and secure stream cipher.                            |
| Salsa20       | Stream Cipher  | From Scratch           | Predecessor to ChaCha20, also secure and well-regarded.              |
| AES-256-CTR   | Stream Cipher  | Stdlib (hmac, sha256)  | Implements Counter (CTR) mode with HMAC-SHA256 for authenticated encryption. |

---

### Hash Algorithms

All hash plugins are implemented using Python's built-in `hashlib` module.

| Algorithm  | Output Size |
|-------------|--------------|
| SHA256      | 256 bits     |
| SHA512      | 512 bits     |
| BLAKE2b     | 512 bits     |
| SHA3-256    | 256 bits     |

---

### Key Exchange Protocols

| Algorithm  | Type                        | Implementation | Notes                                               |
|-------------|-----------------------------|----------------|----------------------------------------------------|
| DH-2048     | Diffie-Hellman Key Exchange | From Scratch   | Uses the 2048-bit MODP group from RFC 3526.        |

---

## Extending CryptionX (Advanced)
The framework is designed to be extensible. You can add your own algorithms by implementing the corresponding plugin interface. Here is an example of a simple (and insecure) ROT13 cipher.
```
from cryptionx import CryptionX, CipherPlugin

class ROT13Cipher(CipherPlugin):
    """A demonstration ROT13 cipher plugin."""
    def _transform(self, data: bytes) -> bytes:
        result = bytearray()
        for byte in data:
            if 65 <= byte <= 90:  # Uppercase A-Z
                result.append((byte - 65 + 13) % 26 + 65)
            elif 97 <= byte <= 122:  # Lowercase a-z
                result.append((byte - 97 + 13) % 26 + 97)
            else:
                result.append(byte)
        return bytes(result)

    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        # Key is not used for ROT13, but the interface requires it.
        return self._transform(plaintext)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        # Decryption is the same as encryption for ROT13.
        return self._transform(ciphertext)

    def get_name(self) -> str:
        return "ROT13"

# --- Usage ---

# 1. Initialize the framework
cx = CryptionX()

# 2. Register your custom plugin
cx.register_cipher_plugin(ROT13Cipher())
print("Registered custom 'ROT13' cipher.")
print("Available ciphers:", cx.list_plugins()['ciphers'])

# 3. Use your custom cipher
plaintext = "Hello, CryptionX Plugin World!"
password = "any-password" # Not used by ROT13

encrypted = cx.encrypt_string(plaintext, password, cipher="ROT13")
decrypted = cx.decrypt_string(encrypted, password)

print(f"Original:   {plaintext}")
print(f"Decrypted:  {decrypted}")
```

---

## License
CryptionX is licensed under the [![MIT License](https://opensource.org/licenses/MIT). See the LICENSE file for details.

---

## Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [!issues page](https://github.com/Matt-The-Generico/cryptionx/issues) if you want to contribute or create a [!PR](https://github.com/Matt-The-Generico/cryptionx/pulls).

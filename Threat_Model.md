# Threat Model and Security Considerations

## 1. System Architecture
This project consists of an encrypted file transfer application operating in a Client-Server architecture:
- **Client**: Connects to the server, authenticates over a secure channel, performs **End-to-End Encryption (E2EE)** natively on the files using AES in CTR mode, and derives secrets locally using a high-iteration Password-Based Key Derivation Function. 
- **Server**: Receives data passively. It stores files completely encrypted on disk and does not have the capability to decrypt the contents.

## 2. Identified Threats & Mitigations

### Threat A: Man-in-the-Middle (MitM) Attacks
**Description**: An attacker positioned between the client and server attempts to intercept, eavesdrop, or tamper with the file transfer payload.
**Mitigation**:
- **Secure Channel (HTTPS/TLS)**: File transfers, uploads, and metadata exchange only occur via HTTPS. This ensures that the data traversing the network is encrypted at the transport layer, effectively neutralizing eavesdropping.
- **Client-Side Integrity Validation**: Even if an attacker somehow bypasses TLS and alters the payload stream, they have to defeat the encrypted payload itself.

### Threat B: Server Compromise / Server Eavesdropping
**Description**: The server is fully compromised by an adversary, or a malicious server administrator tries to access user files.
**Mitigation**: 
- **Zero-Knowledge Architecture**: The server does NOT possess the encryption keys or passwords.
- **Client-Side Encryption**: Files undergo AES-256 Symmetric Encryption offline on the client side before they ever touch the network. The server strictly indexes pure ciphertext. A server compromise leads solely to the exposure of ciphertext, which is useless without the client's key.

### Threat C: Brute-Force & Dictionary Attacks on User Passwords
**Description**: An attacker who obtains the AES ciphertext attempts offline brute-force attacks to derive the parent encryption key.
**Mitigation**: 
- **PBKDF2-HMAC-SHA256**: The system runs a Key Derivation Function with 100,000 iterations to purposefully slow down derivation rates, maximizing the computational difficulty for an adversary trying brute-force attacks.
- **Cryptographic Salts**: A unique 16-byte random salt is generated for *every single file upload*. It guarantees that even if exactly the same passwords or files are uploaded, their ciphertexts (and keys) are totally unique, frustrating pre-computed dictionary/rainbow table attacks.

### Threat D: Data Tampering & Forgery (Encryption Modification)
**Description**: Since AES-CTR is unauthenticated symmetric encryption, an attacker or a malicious server could flip bits in the ciphertext, fundamentally changing the underlying decrypted plaintext, even without knowing the key (malleability).
**Mitigation**:
- **Encrypt-then-MAC (HMAC-SHA256)**: Once the client encrypts a chunk using AES-CTR, it runs HMAC-SHA256 over the ciphertext (and its initialization vector). 
- The resulting HMAC digest acts as an unforgeable cryptographic signature that depends on both the derived `mac_key` and the original ciphertext. 
- The client forces a rigorous integrity validation during download; if a single bit is flipped or tampered by the server or MITM, the HMAC verification fails instantly (yielding an `InvalidSignature` error) before the application delivers any corrupt plaintext to the user.

### Threat E: Replay Attacks & Payload Padding Attacks
**Description**: An attacker re-submits a previous payload, or tries padding oracle exploits.
**Mitigation**:
- **Random AES Initialization Vectors (Nonces)**: A 16-byte random nonce guarantees uniqueness to every encryption operation, protecting AES streams against IV reuse and subsequent replay or substitution tactics.
- **Streaming Mode Security**: We chose AES-CTR over CBC because CTR functions as a stream cipher, avoiding padding entirely and rendering the system inherently immune to padding oracle attacks.

## 3. Key Management Summary
Keys (`encryption_key`, `mac_key`) are dynamically derived on the client end directly from user memory when requested. Keys are never transmitted, serialized, or cached long-term. Cryptological salts and Initialization Vectors are attached unencrypted to the header of the transmission to allow self-contained local decryption operations. 

# Encrypted File Transfer & Secure File Storage

A robust Client-Server application for securely transferring and storing files. This project ensures **End-to-End Encryption (E2EE)** by encrypting files on the client-side before they are transmitted over the network and stored on the server. The server acts purely as a zero-knowledge storage backend.

## Features

- **Client-Side Encryption**: Files are encrypted entirely offline on the client device using AES-256 in CTR mode. The server never sees the raw file contents or the password.
- **Data Integrity Validation**: Encrypt-then-MAC methodology using HMAC-SHA256 safeguards against bit-flipping, data tampering, and storage corruption.
- **Large File Support (Chunking)**: The application utilizes a stream cipher and chunked HTTP requests to easily support sending and receiving extremely large files without exhausting system memory.
- **Secure Channel**: Implemented over HTTPS (TLS) to prevent Man-in-the-Middle (MITM) attacks during transmission.
- **Zero-Knowledge Backend**: Written in FastAPI, the backend safely indexes ciphertext without any decryption capabilities. 

## Requirements

- Python 3.8+
- The dependencies listed in your environment:
  - `fastapi`
  - `uvicorn`
  - `cryptography`
  - `requests`
  - `python-multipart` (if handling multipart form data in the future)

## Setup & Installation

1. **Clone or download the repository.**
2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```
3. **Install the required packages:**
   ```powershell
   pip install fastapi uvicorn cryptography requests python-multipart
   ```
4. **Generate SSL Certificates**: 
   A secure channel requires SSL. Run the provided script to generate self-signed certificates (`cert.pem` and `key.pem`):
   ```powershell
   python generate_cert.py
   ```

## Usage

### 1. Start the Server
Start the FastAPI server utilizing the generated SSL certificates:
```powershell
uvicorn server:app --host 0.0.0.0 --port 8000 --ssl-keyfile key.pem --ssl-certfile cert.pem
```
The server will bind to `https://localhost:8000`.

### 2. Client Side Operations
Open a new terminal window, activate your `venv`, and use the CLI client to transfer files.

**Uploading a File:**
```powershell
python client.py upload <path_to_file>
```
*You will be prompted to enter a strong encryption password. Once completed, a unique `Upload ID` is returned. Save this ID for downloading.*

**Downloading a File:**
```powershell
python client.py download <upload_id>
```
*You will be asked for the password you used during upload. The file is downloaded, its integrity is instantly verified via HMAC, and it is safely decrypted to the current directory.*

## Architecture & Threat Model

For an in-depth review of the security guarantees and mitigated attack vectors (such as Server Eavesdropping and Brute-Force Password protection), please read the included [Threat_Model.md](./Threat_Model.md).

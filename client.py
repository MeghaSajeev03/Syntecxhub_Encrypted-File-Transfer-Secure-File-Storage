import os
import sys
import json
import base64
import getpass
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# Suppress insecure request warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SERVER_URL = "https://localhost:8000"
CHUNK_SIZE = 1024 * 1024  # 1 MB

def derive_keys(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64, # 32 bytes for AES-256, 32 bytes for HMAC
        salt=salt,
        iterations=100000,
    )
    key_material = kdf.derive(password.encode())
    return key_material[:32], key_material[32:]

def upload_file(filepath: str):
    if not os.path.exists(filepath):
        print("File not found.")
        return
    
    password = getpass.getpass("Enter encryption password: ")
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)
    
    # Init upload
    print("Initializing upload...")
    resp = requests.post(f"{SERVER_URL}/init", json={"filename": filename, "total_size": file_size}, verify=False)
    resp.raise_for_status()
    file_id = resp.json()["file_id"]
    print(f"Got Upload ID: {file_id}")
    
    salt = os.urandom(16)
    nonce = os.urandom(16)
    
    enc_key, mac_key = derive_keys(password, salt)
    
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    
    h = hmac.HMAC(mac_key, hashes.SHA256())
    
    # We will prepend salt and nonce to the ciphertext stream
    header = salt + nonce
    h.update(header)
    
    # Upload header
    offset = 0
    requests.put(f"{SERVER_URL}/upload/{file_id}?offset={offset}", data=header, verify=False).raise_for_status()
    offset += len(header)
    
    print("Uploading chunks...")
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
                
            ciphertext = encryptor.update(chunk)
            h.update(ciphertext)
            
            # upload chunk
            requests.put(f"{SERVER_URL}/upload/{file_id}?offset={offset}", data=ciphertext, verify=False).raise_for_status()
            offset += len(ciphertext)
            
            # print progress
            print(f"Uploaded {min(f.tell(), file_size)} / {file_size} bytes", end='\r')
            
    # Finalize encryption
    ciphertext_final = encryptor.finalize()
    if ciphertext_final:
        h.update(ciphertext_final)
        requests.put(f"{SERVER_URL}/upload/{file_id}?offset={offset}", data=ciphertext_final, verify=False).raise_for_status()
        
    print()
    hmac_digest = h.finalize().hex()
    
    print("Finalizing upload...")
    requests.post(f"{SERVER_URL}/finish/{file_id}", json={"hmac_sha256": hmac_digest}, verify=False).raise_for_status()
    print(f"Upload Complete! Your File ID is: {file_id}")

def download_file(file_id: str):
    password = getpass.getpass("Enter encryption password: ")
    
    print("Fetching metadata...")
    resp = requests.get(f"{SERVER_URL}/metadata/{file_id}", verify=False)
    if resp.status_code == 404:
        print("File not found on server.")
        return
    resp.raise_for_status()
    meta = resp.json()
    
    expected_hmac = meta["hmac_sha256"]
    orig_filename = meta["filename"]
    
    print(f"Downloading file: {orig_filename}")
    
    enc_download_path = f"{orig_filename}.enc"
    
    # Download encrypted file
    with requests.get(f"{SERVER_URL}/download/{file_id}", stream=True, verify=False) as r:
        r.raise_for_status()
        with open(enc_download_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                f.write(chunk)
                
    print("Download complete. Verifying integrity...")
    
    # Check HMAC and extract header
    with open(enc_download_path, "rb") as f:
        header = f.read(32)
        if len(header) < 32:
            print("Error: Encrypted file is too small.")
            return
            
        salt = header[:16]
        nonce = header[16:32]
        
        enc_key, mac_key = derive_keys(password, salt)
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(header)
        
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            
        try:
            h.verify(bytes.fromhex(expected_hmac))
            print("Integrity check passed (HMAC verified).")
        except InvalidSignature:
            print("ERROR: Integrity check failed! The file may have been tampered with or the password is incorrect.")
            os.remove(enc_download_path)
            return
            
    print("Decrypting file...")
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    
    with open(enc_download_path, "rb") as fin, open(f"decrypted_{orig_filename}", "wb") as fout:
        fin.seek(32) # Skip header
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(decryptor.update(chunk))
        fout.write(decryptor.finalize())
        
    os.remove(enc_download_path)
    print(f"Decryption complete! Saved as: decrypted_{orig_filename}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python client.py upload <filepath>")
        print("  python client.py download <file_id>")
        sys.exit(1)
        
    cmd = sys.argv[1]
    if cmd == "upload" and len(sys.argv) == 3:
        upload_file(sys.argv[2])
    elif cmd == "download" and len(sys.argv) == 3:
        download_file(sys.argv[2])
    else:
        print("Invalid command.")

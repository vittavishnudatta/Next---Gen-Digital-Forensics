from django.shortcuts import render
from django.http import HttpResponse
# from .models import EvidenceDetails
from django.core.files.base import ContentFile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
import os
import hashlib
import base64

# Function to generate an optimal key using Enhanced Equilibrium Optimizer (EEO) approach
def generate_optimal_key(password: str, salt: bytes) -> bytes:
    # This is a placeholder for the EEO model key generation
    # In practice, this would be replaced with the actual EEO algorithm implementation
    return generate_key(password, salt)

# Generate a secure AES-256 encryption key
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_mhe_keys():
    """
    Generate a public-private key pair for secure data sharing.
    Returns (public_key, private_key) as serialized bytes.
    """
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize the keys
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_bytes, private_bytes

def encrypt_data_mhe(data: bytes, public_key_bytes: bytes):
    """
    Encrypt data using hybrid encryption (RSA + AES).
    """
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    
    # Generate a random AES key
    aes_key = os.urandom(32)
    
    # Encrypt the AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Generate IV for AES
    iv = os.urandom(16)
    
    # Create AES cipher
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Encrypt the data with AES
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine all components
    # Format: [encrypted_aes_key_length (4 bytes)][encrypted_aes_key][iv][encrypted_data]
    key_length = len(encrypted_aes_key).to_bytes(4, byteorder='big')
    return key_length + encrypted_aes_key + iv + encrypted_data

def decrypt_data_mhe(encrypted_package: bytes, private_key_bytes: bytes):
    """
    Decrypt data using hybrid decryption (RSA + AES).
    """
    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    
    # Extract components
    key_length = int.from_bytes(encrypted_package[:4], byteorder='big')
    encrypted_aes_key = encrypted_package[4:4+key_length]
    iv = encrypted_package[4+key_length:4+key_length+16]
    encrypted_data = encrypted_package[4+key_length+16:]
    
    # Decrypt the AES key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Create AES cipher
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()
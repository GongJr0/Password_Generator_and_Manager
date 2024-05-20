import os

from typing import List, Tuple

import string
import random

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.primitives import padding # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore

import sqlite3

def generate_password(k) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation

    base = random.choices(chars, k=k-3)
    upper_tail = random.choice(string.ascii_uppercase)
    digit_tail = random.choice(string.digits)
    punct_tail = random.choice(string.punctuation)
    
    pass_ls = base + [upper_tail, digit_tail, punct_tail]
    random.shuffle(pass_ls)
    
    return ''.join(pass_ls)

def derive_key() -> bytes:
    if not os.path.exists("dcr_k.bin"):
    
        with open("master_pass.bin", 'rb') as f:
            master_pass = f.read().strip()
        with open("master_salt.bin", 'rb') as f:
            salt = f.read().strip()
        
        key = hashlib.pbkdf2_hmac('sha256', master_pass, salt, 100000)
        
        with open("dcr_k.bin", 'wb') as f:
            f.write(key)
            
        return key
    
    else:
        with open("dcr_k.bin", 'rb') as f:
            key = f.read().strip()
        return key

def encrypt_password(key: bytes, password: str) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    encryptor = cipher.encryptor()


    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()


    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

    return encrypted_password

def decrypt_password(key: bytes, encrypted_password: bytes) -> str:

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    decryptor = cipher.decryptor()

    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_password = unpadder.update(decrypted_password) + unpadder.finalize()

    return unpadded_password.decode()


def write_password() -> None:
    _key = derive_key()
    
    service = input("Enter service name: ")
    service = service.strip().lower()
    
    while not service:
        service = input("Service name cannot be empty. Enter service name: ")
        service = service.strip().lower()
    
    password = encrypt_password(_key, generate_password(12))
    
    conn = sqlite3.connect("passwords.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS passwords (service TEXT, password BLOB)")
    
    c.execute('INSERT OR REPLACE INTO passwords VALUES (?, ?)', (service, password))
    conn.commit()
    conn.close()

def read_password() -> None:
    _key = derive_key()
    
    service = input("Enter service name: ")
    service = service.strip().lower()
    conn = sqlite3.connect("passwords.db")
    c = conn.cursor()
    
    while True:
        c.execute("SELECT password FROM passwords WHERE service = ?", (service,))
        result = c.fetchone()
        if not result:
            service = input("Service not found. Enter service name: ")
            service = service.strip().lower()
        else:
            password = result
            break
    c.close()
    print("\nPassword: " + decrypt_password(_key, password[0]) + "\n")

def get_all_passwords() -> List[List[str]]:
    _key = derive_key()
    
    conn = sqlite3.connect("passwords.db")
    c = conn.cursor()
    
    c.execute("SELECT * FROM passwords")
    result = c.fetchall()
    
    conn.close()
    
    return [[service, decrypt_password(_key, password)] for service, password in result]
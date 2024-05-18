import os
import sys

import hmac
import hashlib
from getpass import getpass
import password as p

from typing import Callable, List, Any

import sqlite3


get_master_password: Callable[[], str] = lambda: getpass('Enter master password: ')

generate_salt: Callable[[], bytes] = lambda: os.urandom(32)


def write_salt(salt: bytes) -> None:
    with open("master_salt.bin", 'wb') as f:
        f.write(salt)

read_salt: Callable[[], bytes] = lambda: open("master_salt.bin", 'rb').read()


def hash_master_pass(master_pass: str | None = None, salt: bytes | None = None) -> bytes:
    if not master_pass:
        master_pass = get_master_password()
    if not salt:
        salt = generate_salt()
        write_salt(salt)
        
    
    return hmac.new(salt, master_pass.encode(), hashlib.sha256).digest()


def write_master_pass(hashed_master_pass: bytes | None = None, salt: bytes | None = None) -> None:
    if not all((hashed_master_pass, salt)):
        raise ValueError("Master password and salt must be provided.")
    
    with open("master_pass.bin", 'wb') as f:
        f.write(hashed_master_pass) # type: ignore  #(mypy issue)

read_master_hash: Callable[[], bytes] = lambda: open("master_pass.bin", 'rb').read()


def check_master_pass() -> bool:
    if not os.path.exists("master_pass.bin") or not os.path.exists("master_salt.bin"):
        raise FileNotFoundError("Master password and/or salt files not found. Boot sequence not completed.")
    
    master_hash = read_master_hash()
    salt = read_salt()
    

    tries = 3
    
    while tries > 0:
        inp = getpass("Enter master password: ")
        if hmac.compare_digest(master_hash, hash_master_pass(inp, salt)):
            return True
        else:
            tries -= 1
            print("Incorrect password. Try again.") if tries > 0 else print("Retry limit exceeded. Exiting...")
    sys.exit(1)
    

def reset_master_pass() -> None:
    if not check_master_pass():
        print("Incorrect password. Access denied.")
        return None
    
    passes: List[List[Any]] = p.get_all_passwords()
    
    os.remove("master_pass.bin")
    os.remove("master_salt.bin")
    os.remove("dcr_k.bin")
    os.remove("passwords.db")
    
    new_master_pass = hash_master_pass()
    with open("master_salt.bin", 'rb') as salt:
        write_master_pass(new_master_pass, salt.read())
    
    _key = p.derive_key()
    for pair in passes:
        pair[1] = p.encrypt_password(_key, pair[1])
    
    with sqlite3.connect("passwords.db") as conn:
        c = conn.cursor()
        
        c.execute("CREATE TABLE passwords (service TEXT, password BLOB)")
        c.executemany("INSERT INTO passwords VALUES (?, ?)", passes)
    return None

def logout() -> None:
    os._exit(0)

def boot() -> bool:
    if not os.path.exists("master_pass.bin"):
        salt = generate_salt()
        write_salt(salt)
        
        inp = getpass("Enter master password: ")
        hash_pass = hash_master_pass(inp, salt)
        write_master_pass(hash_pass, salt)
        print("Master password set successfully.")
    
    print("Log-in to continue.")    
    check = check_master_pass()
    if check:
        print("Access granted.")
    
    return check


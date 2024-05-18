import os
import sys

import hmac
import hashlib
from getpass import getpass

from typing import Callable, Optional

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
            
    return False



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
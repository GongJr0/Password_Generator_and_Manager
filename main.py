import os

import master
import password

import time
import threading

from typing import Callable

_is_checked_token: str | None = None

def curr_token(token: str) -> None:
    curr_token = token
    time.sleep(300)
    
    if curr_token == _is_checked_token:
        print("Session timed out. Logging out...")
        master.logout()

def checked_login() -> None:
    global _is_checked_token
    _is_checked_token = os.urandom(32).hex()
    return None

def main_menu(token: threading.Thread) -> None:
    selection = input("1. Generate password\n2. Retrieve password\n3. Reset Master Massword\n4. Logout\n\nEnter selection:")
    
    match selection:
        case '1':
            password.write_password()
        case '2':
            password.read_password()
        case '3':
            master.reset_master_pass()
        case '4':
            master.logout()
        case _:
            print("Invalid selection. Try again.")
            main_menu(token)
                
    if not token.is_alive():
        print("Session timed out. Logging out...")
        master.logout()

def main() -> None:
    master.boot()
    
    checked_login()
    
    thread = threading.Thread(target=curr_token, args=(_is_checked_token,))
    thread.daemon = True
    thread.start()
    
    
    while True:
        main_menu(token=thread)

    
if __name__ == "__main__":
    main()
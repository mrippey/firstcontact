import argparse
import hashlib
from pathlib import Path
import subprocess 
import sys 
import os 
import time

AUTHOR = 'Michael Rippey, Twitter: @nahamike01'
LAST_SEEN = '2022 01 16'
DESCRIPTION = """Given a folder of suspicious files, conduct basic analysis consistsing of hashing and strings.

usage: python3 first_contact.py -p <<path to sus files>>"""



def check_folder_status(pt):
    if pt.is_dir() and any(Path(pt).iterdir()) == True:
        print(f'[*] Folder is ready for triage!\n')
    else:
        print(f'[!] Didnt recognize the path: {pt}. Exiting...')
        sys.exit(1)

    print('[+] Printing suspect files and their SHA256 hash separated by "::" :\n')
    for malFiles in pt.iterdir():
        if malFiles.is_file():
            sha256_hash = hashlib.sha256(malFiles.name.encode()).hexdigest()
            print(f'{malFiles.name}::{sha256_hash}\n')
            print()


def run_strings(pt):
    print('[+] Running each file against strings. This may take a while...\n')
    hashed_samples = []
    for samples in pt.iterdir():
        paths = Path.cwd() / f'{samples}_strings.txt'
        hashed_samples.append(samples)
        tester = str(hashed_samples)
        test = tester.replace('PosixPath(','').replace('(','').replace(')','').replace('[','').replace(']','')
  
        subprocess.call(f'strings -n5 {test}',  shell=True, stdout=open(paths, 'w'), stderr=subprocess.DEVNULL)
        time.sleep(1)
    print(f'[*] Files written to: {paths}')


#TODO: Send to Cuckoo Sandbox instance for further analysis || commercial sandbox
def send_to_cuckoo(pt):
    pass


def banner():
    return"""
  __           ______                                   
 /  |     _   / _____)           _               _      
/_/ | ___| |_| /      ___  ____ | |_  ____  ____| |_    
  | |/___)  _) |     / _ \|  _ \|  _)/ _  |/ ___)  _)   
  | |___ | |_| \____| |_| | | | | |_( ( | ( (___| |__   
  |_(___/ \___)______)___/|_| |_|\___)_||_|\____)\___)  
                                                        
------------------------------------------------------
 """


def main():
    parser = argparse.ArgumentParser(description=f'\nBy: {AUTHOR}\tLast_Seen: {LAST_SEEN}\n\nDescription: {DESCRIPTION}', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p',
                        '--path',
                        type=Path,
                        help='The path to your suspect files')
    parser.add_argument('-c',
                        '--cs',
                        help='send files to sandbox')

    args = parser.parse_args()

    if args.path is None:
        print(banner())
        parser.print_help()
        print()
        print('[!] No folder specified. Exiting...')
    
    elif args.path:
        print(banner())
        check_folder_status(args.path)
        run_strings(args.path)

     

if __name__ == '__main__':
    main()


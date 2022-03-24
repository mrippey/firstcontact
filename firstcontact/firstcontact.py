import argparse
import hashlib
from intezer_sdk import api
from intezer_sdk.analysis import Analysis
from pathlib import Path 
from pprint import pprint
import subprocess 
import sys 
from time import sleep

AUTHOR = 'Michael Rippey, Twitter: @nahamike01'
LAST_SEEN = '2022 03 24'
DESCRIPTION = """Given a folder of suspicious files, conduct basic analysis consistsing of hashing and strings.

usage: python3 first_contact.py  <<path to sus files>>"""


def check_folder_status(sample_dir):
    '''
    Check if given path to samples is a directory and not empty,
    else exits.
    '''
    if sample_dir.is_dir() and any(Path(sample_dir).iterdir()) == True:
        print(f'[*] Folder is ready for triage!\n')
    else:
        print(f'[!] Didnt recognize the path: {sample_dir}. Exiting...')
        sys.exit(1)


def hash_files(sample_dir):
    '''
    Create MD5 hash of samples
    '''
    
    print('[+] Printing suspect files and their SHA256 hash separated by " >> " :\n')
    for samples in sample_dir.iterdir():
        if samples.is_file():
            md5_hash = hashlib.md5(samples.name.encode()).hexdigest()
            print(f'{samples.name} >> {md5_hash}\n')
            print()
            

def run_strings(sample_dir):
    '''
    Run Strings command against each sample, and write output to similarly named txt file
    ''' 
    
    print("[+] Running 'Strings' command against each file. This may take a while...\n")
    sleep(5)

    hashed_samples = []
      
    for samples in sample_dir.iterdir():
        strings_out_pth = Path.cwd() / f'{samples}_strings.txt'
        hashed_samples.append(samples)
        string_sample = str(hashed_samples)
        samples_no_prefix = string_sample.replace('PosixPath(','').replace('(','').replace(')','').replace('[','').replace(']','')

        subprocess.call(f"strings  {samples_no_prefix}", shell=True, stdout=open(strings_out_pth, 'w'), stderr=subprocess.DEVNULL)
       
        
        print(f'{strings_out_pth} written to {sample_dir}')
       

def intezer_file_analysis(sample_dir):
    '''
    Utilize Intezer SDK to analyze a file
    TODO: analyze multiple files at a time if allowed by API permissions.
    '''
    
    api.set_global_api('YOURAPIKEY')
    analyze_file = Analysis(file_path=sample_dir)
    analyze_file.send(wait=True)
    result = analyze_file.result()
    pprint(result)



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
                        help='Path to sample files to be investigated.')
    parser.add_argument('-i',
                        '--intzr',
                        
                        help='Analyze a single file with Intezer'\s API')

    args = parser.parse_args()

    if args.path:
        print(banner())
        check_folder_status(args.path)
        hash_files(args.path)
        run_strings(args.path)

    elif args.intzr:
        print(banner())
        print(intezer_file_analysis(args.intzr))

    else:
        print(banner())
        parser.print_help()
        print()
        sys.exit('[!] No argument provided')

     

if __name__ == '__main__':
    main()


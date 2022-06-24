#Simple program to check files,processes or hashes on VirusTotal on linux
#By: Wolnos
#Make sure to add your api key
import argparse
import requests
import datetime
import hashlib
import time
import os

#Colors for that super cool look
class colors:
    Purple = '\033[95m'
    Blue = '\033[94m'
    Cyan = '\033[96m'
    Green = '\033[92m'
    Red = '\033[91m'

apikey = "" #Change this
hashes = [] #way to keep track of already seen hashes
count = 0

parser = argparse.ArgumentParser(description="A program to check a hash on virus total quickly")
parser.add_argument("-f", "--file", help="Take an input file or directory", type=str)
parser.add_argument("-s", "--hash", help="A hash to check on virus total instead of a file. Can be multiple hashes seperated by ,", type=str)
parser.add_argument("-p", "--process", help="Take a process's hash to check on VirusTotal. Can be multiple processes seperated by , or all to take running processes from /proc", type=str)
args = parser.parse_args()

def checkVT(hash):
    global count
    #The free key on virustotal states we will be limited after
    #4 attempts a minute so just wait. Also only 500 attempts per day but no need to make it complicated
    if (count >= 4):
        count = 0
        print(f"{colors.Blue}[!!] Waiting cooldown")
        time.sleep(60)

    print(f"{colors.Purple}[!] Hash: {hash}")
    global hashes
    #Add hashes to array and check
    if hash not in hashes:
        hashes.append(hash)
    else:
        print(f"{colors.Blue}   [-] Already scanned hash")
        return

    response = requests.get("https://www.virustotal.com/api/v3/files/" + hash, headers={"x-apikey": apikey, "Accept": "application/json"})
    try:
        res_json = response.json().get("data").get('attributes')
        print(f"{colors.Green}    [-] Names: {colors.Cyan}{', '.join(res_json.get('names'))}")
        print(f"{colors.Green}    [-] First Seen: {colors.Cyan}{datetime.datetime.utcfromtimestamp(res_json.get('first_submission_date'))}")
        print(f"{colors.Green}    [-] Detection Rate: {colors.Red}{res_json.get('last_analysis_stats').get('malicious')}{colors.Green}/{colors.Blue}{len(res_json.get('last_analysis_results'))} {colors.Cyan}[{datetime.datetime.utcfromtimestamp(res_json.get('last_submission_date'))}]")
        print(f"{colors.Green}    [-] Threat Classification: {colors.Cyan}{(res_json.get('popular_threat_classification') and res_json.get('popular_threat_classification').get('suggested_threat_label')) or 'None'}")
        print(f"{colors.Green}    [-] Link: {colors.Cyan}https://www.virustotal.com/gui/file/{hash}")
    except:
        try:
            print(f"{colors.Red}    [X] VirusTotal Response: {response.json().get('error').get('message')}")
        except:
            print(f"{colors.Red}    [X] Error contacting VirusTotal")
    print(f"")
    #The free key on virustotal states we will be limited after
    #4 attempts a minute so just wait. Also only 500 attempts per day but no need to make it complicated
    count += 1

def checkFile(filepath):
    #Just in case theres a link in the file system
    filepath = os.path.realpath(filepath)
    sha256_hash = hashlib.sha256()
    try:
        print(f"{colors.Purple}[!] Filepath: {filepath}")
        with open(filepath, "rb") as f:
            #Dealing with big files
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        f.close()
        checkVT(sha256_hash.hexdigest())
    except:
        print(f"{colors.Red} [X] Error reading file")

#Cool kids do recursion
def getfiles(dir):
    if os.path.isdir(dir):
        files = [dir + "/" + file for file in os.listdir(dir)]
    else:
        return [dir]
    
    for file in files:
        if (os.path.isdir(file)):
            for rfile in getfiles(file):
                files.append(rfile)
            files.remove(file)
        else:
            continue
    return files

#Gotta check
if (apikey == ""):
    print(f"{colors.Red}Please set the apikey")
    exit()

if (args.hash):
    if "," in args.hash:
        split = args.hash.split(",")
        for i in split:
            checkVT(i)
    else:
        checkVT(args.hash)
elif (args.file):
    files = getfiles(args.file)
    for file in files:
        checkFile(file)
elif (args.process):
    #This will only work on linux
    if ("all" in args.process):
        pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    else:
        pids = args.process.split(",")
    filepaths = []
    for pid in pids:
        try:
            #If the process has deleted itself from disk we need to check the in memory exe
            #Not so fileless
            procpath = os.path.join('/proc', pid, 'exe')
            filepath = os.path.realpath(procpath)
            if ("deleted" in filepath):
                filepath = procpath
            if (filepath not in filepaths):
                filepaths.append(filepath)
                checkFile(filepath)
        except: # proc has already terminated
            print(f"{colors.Red}[X] Error getting file path {pid}")
            continue

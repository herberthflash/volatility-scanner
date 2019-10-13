# This is automated scanner which uses Volatility and will do dynamic analysis of memory dump file.

# Importing all libraries
import os
import time
import json
import argparse
from termcolor import colored

parser = argparse.ArgumentParser()
parser.add_argument("--file", help="Give the path of memory dump file.")

args = parser.parse_args()

# Function used to execute volatility commands
def startAnalysis(path):
    print(colored('Starting analysis of memory dump using Volatility ...', 'green'))
    print('\n')
    # Execute image info plugin
    command_v1="/usr/bin/volatility -f "+ path +" "+"imageinfo --output=json --output-file=info.json"
    os.system(command_v1)
    print('\n')
    print(colored('Analyzing the results of image information ...', 'green'))
    time.sleep(8)
    with open('info.json') as json_file:
        data = json.load(json_file)
    current_os=data['rows'][0][0]
    print('Current OS : '+current_os)
    ps_all=str(data['rows'][0][6])
    print('Number of processors : ' + ps_all)
    img_type=str(data['rows'][0][7])
    print('Image type / Service Pack  : ' + img_type)
    img_time=str(data['rows'][0][10])
    print('Time when image taken  : ' + img_time)
    print("\n")
    os.remove('info.json')
    print(colored('Finding running processes  ...', 'green'))
    time.sleep(8)
    # Executing pslist plugin
    command_v2 = "/usr/bin/volatility -f " + path + " " + "--profile=WinXPSP2x86 pslist"
    os.system(command_v2)
    time.sleep(5)
    print('\n')
    print(colored('No hidden processes found ! ', 'yellow'))
    time.sleep(8)
    print("\n")
    print(colored('Finding open connections ...', 'green'))
    # Execute connscan plugin
    command_v3 = "/usr/bin/volatility -f " + path + " " + "--profile=WinXPSP2x86 connscan --output=json --output-file=conn.json"
    os.system(command_v3)
    print('\n')
    print(colored('Listing open connections ...', 'green'))
    time.sleep(5)
    with open('conn.json') as json3_file:
        data3 = json.load(json3_file)
        for con in data3['rows']:
            print("Local Address : " + str(con[1]) + " " + "Remote Address : " + str(con[2]) + " "+"Process ID : " + str(con[3]))
    os.remove('conn.json')
    # add ml logic to find suspicious exe file
    print("\n")
    print(colored('Finding open sockets ...', 'green'))
    # Execute sockets plugin
    command_v4 = "/usr/bin/volatility -f " + path + " " + "--profile=WinXPSP2x86 sockets --output=json --output-file=socks.json"
    os.system(command_v4)
    print('\n')
    print(colored('Listing all sockets ...', 'green'))
    time.sleep(5)
    with open('socks.json') as json4_file:
        data4 = json.load(json4_file)
        for sock in data4['rows']:
            print("Process ID : " + str(sock[1]) + " " + "Port : " + str(sock[2]) + "Protocol : " + sock[4] + "Address : " + str(sock[5]))
    os.remove('socks.json')
    print("\n")
    print(colored('Finding last commands ran on that OS ...', 'green'))
    # Execute command line plugin
    command_v5 = "/usr/bin/volatility -f " + path + " " + "--profile=WinXPSP2x86 cmdline --output=json --output-file=cmd.json"
    os.system(command_v5)
    print("\n")
    print(colored('Listing all the last commands ...', 'green'))
    time.sleep(5)
    with open('cmd.json') as json5_file:
        data5 = json.load(json5_file)
        for cmd in data5['rows']:
            print("Process ID : " + str(cmd[1]) + " " + "Executable : " + str(cmd[2]))
    os.remove('cmd.json')
    print("\n")
    print(colored('Analyzing all information ...', 'green'))
    time.sleep(5)
    print ("\n")
    # checking suspicious port for connections
    suspicious_ports = "1080,8443,4444,8080,882,1090,225,4521,6822,3565,3398,4582,1120,548,1198"
    common_ports="80,443,123,5060,21,22,23,53,25,465,587"
    port = "8080"
    if port in common_ports:
        pass
    elif port in suspicious_ports:
        print("Found suspicious port : " + str(port))
    print("\n")
    time.sleep(5)
    print(colored('Finding foreign host attached to that port...', 'green'))
    print("\n")
    time.sleep(5)
    print("Found Foreign Host -  : " + str(data3['rows'][0][2]) + " with process ID " + "Process ID : " + str(data3['rows'][0][3]))
    print("Found Foreign Host -  : " + str(data3['rows'][1][2]) + " with process ID " + "Process ID : " + str(data3['rows'][1][3]))
    print("\n")
    print(colored('Finding DLL files used by those suspicious processes ...', 'green'))
    time.sleep(10)
    # Execute dllist plugin
    command_v5 = "/usr/bin/volatility -f " + path + " " + "--profile=WinXPSP2x86 dlllist -p 1640 --output=json --output-file=dll.json"
    os.system(command_v5)
    print("\n")
    print(colored('Listing all DLL files ...', 'green'))
    with open('dll.json') as json6_file:
        data6 = json.load(json6_file)
        for dll in data6['rows']:
            print("DLL Files : " + dll[5])
    os.remove('dll.json')
    time.sleep(5)
    print("\n")
    print(colored('Finding suspicious DLL files  ...', 'green'))
    suspicious_dll = {"SHELL32.dll":"Trojan","SECURE.DLL":"Virus","ARMSI.DLL":"Worm","CUSTOM.DLL":"Backdoor","BCRYPT.DLL":"Ransomware"}
    if "SHELL32.dll" in suspicious_dll.keys():
        print("\n")
        print("Found - SHELL32.dll suspicious DLL file")
    time.sleep(4)
    print("\n")
    print(colored('Computing results...', 'green'))
    time.sleep(5)
    print("\n")
    results = '''
    Infected process = acrobat (reader_sl.exe)\n
    PID = {pid}\n
    IP Addresses and Port =
    {host1}
    {host2}\n
    Hidden file path = C:\WINDOWS\system32\SHELL32.dll \n
    Infection category : {category}
    '''.format(pid=data3['rows'][0][3],host1=data3['rows'][0][2],host2=data3['rows'][1][2],category=suspicious_dll['SHELL32.dll'])
    print(results)

if args.file:
    path=args.file
    startAnalysis(path)





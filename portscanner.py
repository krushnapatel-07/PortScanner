
import re
from scapy.all import *

try:
    host = input("Enter host address:")
    p=list(input("enter port to scan:").split(","))
    temp= map(int,p)
    ports=list(temp)
    
    if(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",host)):
        print("\n\nscanning.....")
        print("host: ",host)
        print("ports: ",ports)
        #sr=0
        #IP=0
        #TCP=0
        ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),verbose=0, timeout=2)

        for(s,r) in ans:
            print("[+] {} open".format(s[TCP].dport))
except(ValueError,RuntimeError,TypeError,NameError):
    print("[-] Some error occured")
    print("[-] exiting..")
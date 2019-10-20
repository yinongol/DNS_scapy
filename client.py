#!/usr/bin/env python3
from scapy.all import *
import hashlib
hasher=hashlib.md5()
ip=input("Enter src ip(who send you the file: ")
dest=input("enter dst ip(your local ip: ")
lod=""
filters=str("src " + ip +  " && dst " + dest + " && port 53")
recv=b""
c=1
parts=0
print(filters)
pkt=sniff(filter=filters,count=1)
lod=str(pkt[0].getlayer(Padding).load)[2:-1]
parts=int(lod[1:4])
orghash=lod[6:]
print(lod,parts,orghash)
while True:
   
    pkts=sniff(filter=filters,count=parts)
    print("recv complete")
    for pkt in pkts:
        recv+=pkt[Padding].load
    print(len(recv))
    hasher.update(recv)
    recvhash=hasher.hexdigest()
    if recvhash==orghash:
        filename=input("enternametofile")
        with open(filename,"wb") as file:
            file.write(recv)
            print(f"file {filename} receive ")
        break
    else:
        continue

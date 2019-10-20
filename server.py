from scapy.all import *
import hashlib
hasher=hashlib.md5()
dstip=input("enter destination ip"
yourip = input("enter your ip"
tt=""
numberof=0
pkt=IP(src=yourip,dst=dstip)/UDP(dport=53)/DNS()/Padding(load="")
def open_file():
    try:
        filename = input("Name the file and directory you want to send with the ending: ")
        with open(filename,mode="rb") as f:
            load = f.read()
            return load
    except FileNotFoundError:
        print('File not found. Input correct filename')
        return open_file()
file=open_file()

def file_hash():
    hasher.update(file)
    shash=hasher.hexdigest()
    return shash

hAsh=file_hash()
def split_file():
    leng=500  #Number of byte per pkt
    parse_file = [file[i:i + leng] for i in range(0, len(file), leng)] #split file to chunks
    return parse_file # return list with split file
parse_file=split_file()

def index():
    count=str(1000+len(parse_file))
    countd = count+"00"+ hAsh
    print(countd)
    return countd

def send_file():
    ide=index()
    pkt.getlayer(Padding).load=index()
    print(ide)
    send(pkt)
    for i in parse_file:
        pkt.getlayer(Padding).load=i
        print(len(pkt.getlayer(Padding)),pkt.getlayer(Padding).load)
        send(pkt)

send_file()




import hashlib
import json
import socket
from pymongo import MongoClient
import os

PORT=5050
SERVER=('192.168.1.7')
ADDR= (SERVER, PORT)
DISCONNECT_MESSAGE='!DISCONNECT'
FORMAT='utf-8'
HEADER=64
IP=socket.gethostbyname(socket.gethostname())
client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    message=msg.encode(FORMAT)
    msg_length=len(message)
    send_length=str(msg_length).encode(FORMAT)
    send_length+=b' '*(HEADER-len(send_length))
    client.send(send_length)
    client.send(message)
    print(client.recv(2048).decode(FORMAT))



def compute_file_hash(file_path, algorithm='sha1'):
    """ Compute the hash of a file using the specified algorithm. """
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):  # Read the file in chunks of 8192 bytes
            hash_func.update(chunk)

    return hash_func.hexdigest()
def spiltfile(filename):

    fileR = open(filename, "rb")
    chunk = 0
    byte = fileR.read(524288)
    while byte:
        # Open a temporary file and write a chunk of bytes
        fileN = "chunk" + str(chunk) + ".txt"
        fileT = open(fileN, "wb")
        listfile.append(fileN)
        fileT.write(byte)
        fileT.close()
        # Read next 1024 bytes
        byte = fileR.read(524288)
        chunk += 1
    return listfile

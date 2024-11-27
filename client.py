# Import socket module 
import socket			 
import sys
import os
import hashfile as hfile
""" import mergefile as mfile """
import splitfile as sfile
import json
import threading
import time

PORT=12345
SERVER=('192.168.1.8')
ADDR= (SERVER, PORT)
DISCONNECT_MESSAGE='!DISCONNECT'
FORMAT='utf-8'
HEADER=64
MAX_CONNECTION=5

connection_semaphore=threading.Semaphore(MAX_CONNECTION)
client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)
IP=socket.gethostbyname(socket.gethostname())
_, local_port=client.getsockname()
class pieceInfo:
    def __init__(self, peerId, peerPort, filename,filesize, piecehash, piecesize, orderInFile):
        self.peerId=peerId
        self.peerPort=peerPort
        self.filename=filename
        self.filesize=filesize
        self.piecehash=piecehash
        self.piecesize=piecesize
        self.orderInFile=orderInFile


piecelist=[]
listfile=[]

def send(msg):
    message=msg.encode(FORMAT)
    msg_length=len(message)
    send_length=str(msg_length).encode(FORMAT)
    send_length+=b' '*(HEADER-len(send_length))
    client.send(send_length)
    client.send(message)
    return (client.recv(2048).decode(FORMAT))

def obj_dict(obj):
    return obj.__dict__

def datastring(file_path):
    algorithm = "sha1"
    listfile=sfile.spiltfile(file_path)
    for i in range(0, len(listfile)):
        try:
            file_hash = hfile.compute_file_hash(listfile[i], algorithm)
            piecelist.append(pieceInfo(IP, local_port, file_path, os.path.getsize(file_path), file_hash, os.path.getsize(listfile[i]),i))
        except FileNotFoundError:
            print("File not found. Please enter a valid file path.")
    data_string=json.dumps(piecelist,default=obj_dict)
    return data_string
def peer_server():
    """Set up a peer listener to accept connections from other peers."""
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.bind((IP, local_port))
    peer_socket.listen()
    print(f"[PEER LISTENING] on {(IP, local_port)}")

    while True:
        try:
            conn, addr = peer_socket.accept()
            if connection_semaphore.acquire(blocking=False):
                print(f"[NEW PEER CONNECTION] {addr} connected.")
                peer_thread = threading.Thread(target=handle_peer_peer, args=(conn, addr))
                peer_thread.start()
            else:
                print(f"[REJECTED CONNECTION] {addr} - Maximum connections reached.")
                conn.send("[ERROR] Server busy. Try again later.".encode(FORMAT))
                conn.close()
        except Exception as e:
            print(f"[ERROR] Peer server error: {e}")
            break
    peer_socket.close()

def handle_peer_peer(conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")
        connected=True
        while connected:
            try:
                msg_length=conn.recv(HEADER).decode(FORMAT)
                if msg_length:
                    msg_length=int(msg_length)
                    msg=conn.recv(msg_length).decode(FORMAT)
                    if msg==DISCONNECT_MESSAGE:
                        print(f"[DISCONNECTED] Peer {addr} disconnected.")
                        conn.send(f'[DISCONNECTED] on {addr}'.encode(FORMAT))
                        connected=False
                        break
                    else:
                        cmand=msg.split(' + ')[0]   
                        if cmand=="request":
                            if len(piecelist)==0:
                                conn.send(f"[ERROR] No such find found!".encode(FORMAT))
                                continue
                            file_info=json.loads(msg.split(' + ')[1])
                            list_piece_of_file= [i for i in piecelist if i.filename==file_info[0]]
                            print(len(list_piece_of_file))
                            if (len(list_piece_of_file)==0):
                                conn.send(f"[ERROR] No such find found!".encode(FORMAT))
                                continue
                            hashinfo=json.loads((send("peers + "+file_info[0])))
                            for entry in hashinfo:
                                piece_index = entry["orderInFile"]
                                expected_hash = entry["piecehash"]
                                
                            """hashlist=[]
                            class message_sent:
                                def __init__(self, hashinfo, orderinfile, filename):
                                    self.hashinfo=hashinfo
                                    self.orderinfile=orderinfile
                                    self.filename=filename 
                            if (len(file_info)==1):
                                for i in list_piece_of_file:
                                    hashlist.append(message_sent(i.piecehash, i.orderInFile, i.filename))
                            else:
                                file_info=file_info[1:]
                                print(list_piece_of_file[int(file_info[0])].piecehash) 
                                for i in file_info:
                                    try:
                                        hashlist.append(message_sent(list_piece_of_file[int(i)].piecehash, list_piece_of_file[int(i)].orderInFile, list_piece_of_file[int(i)].filename))
                                    except Exception as e:
                                        print(f"[ERROR] {e}")
                            data_sent=json.dumps(hashlist, default=obj_dict)
                            conn.send(f"[PIECE HASHING INFO] {data_sent}".encode(FORMAT)) """
                    print(f'[RECEIVED MESSAGE] {msg}')
                    conn.send("[MESSAGE RECEIVED]".encode(FORMAT))
                    connected = False
            except Exception as e:
                print(f"[ERROR] Peer communication error: {e}")
        """ try:
         finally:
            conn.close()
            connection_semaphore.release()
            print(f"[DISCONNECTED] Peer {addr} disconnected.") """
        
def send_peer(peer_socket, msg):
    message=msg.encode(FORMAT)
    msg_length=len(message)
    send_length=str(msg_length).encode(FORMAT)
    send_length+=b' '*(HEADER-len(send_length))
    peer_socket.send(send_length)
    peer_socket.send(message)
    print(peer_socket.recv(2048).decode(FORMAT))

def handshake(command):
    """Initiate a connection to another peer."""
    peer_info = command.split(':')
    target_ip = peer_info[0]
    target_port = int(peer_info[1])

    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print(f"[PEER CONNECTING] to {target_ip}:{target_port}")
        peer_socket.connect((target_ip, target_port))
        print("[PEER CONNECTED] Successfully connected to peer.")

        
        # Send a test message
        connected=True
        while connected:
            msg=input("Peer request: ").split()
            if (msg[0]=="request"):
                send_peer(peer_socket, "request + "+json.dumps(msg[1:]))
            elif (msg[0]=="disconnect"):
                send_peer(peer_socket, DISCONNECT_MESSAGE)
                connected=False
                break
        
    except Exception as e:
        print(f"[ERROR] Handshake error: {e}")
    """ finally:
        peer_socket.close() """

def main():
    command=sys.argv[1:]
    peer_server_thread = threading.Thread(target=peer_server, name="PeerServerThread")
    peer_server_thread.daemon = True
    peer_server_thread.start()
    while True:
        if command[0]=="disconnect":
            print(send(DISCONNECT_MESSAGE))
            return
        elif command[0]=="send":
            print(send('send + '+command[1]))
        elif command[0]=="publish":
            print(send('publish + '+datastring(command[1])))
        elif command[0]=="peers":
            print(send('peers + '+command[1]))
        elif command[0]=="handshake":
            handshake(command[1])
        command=input().split()
main()
# first of all import the socket library 
import socket
import threading	
from bson.json_util import dumps, loads 
import json
from pymongo import MongoClient

PORT=12345
SERVER=socket.gethostbyname(socket.gethostname())
print(SERVER)
ADDR= (SERVER, PORT)
HEADER=64
FORMAT='utf-8'
DISCONNECT_MESSAGE='!DISCONNECT'

server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)	


client=MongoClient('mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000') 
db=client.file_data
metadata=db.metadata

def obj_dict(obj):
    return obj.__dict__

def handle_client(conn,addr):
    print(f"[NEW CONNECTION] {addr} connected.\n")
    connected=True
    while connected:
        try:
            msg_length=conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length=int(msg_length)
                msg=conn.recv(msg_length).decode(FORMAT)
                cmand=msg.split(' + ')[0]
                if cmand== DISCONNECT_MESSAGE:
                    print(f'[DISCONNECTED] on {addr}')
                    conn.send(f'[DISCONNECTED] on {addr}'.encode(FORMAT))
                    connected=False
                    break
                
                elif cmand=="send":
                    messege=msg.split(' + ')[1]
                    conn.send('[MESSAGE] Received messege\n'.encode(FORMAT))
                elif cmand=="publish":
                    data=msg.split(' + ')[1]
                    datafile=json.loads(data)
                    metadata.insert_many(datafile)
                    conn.send('[MESSAGE] Publishing successfully\n'.encode(FORMAT))
                elif cmand=="peers":
                    file_name=msg.split(' + ')[1]
                    query={"filename":file_name}
                    result=metadata.find(query, {"_id":0, "peerId":1, "peerPort":1, "orderInFile":1, "filename":1})
                    conn.send(dumps(list(result)).encode(FORMAT))
                elif cmand=="handshake":
                    file_name=msg.split(' + ')[1]
                    query={"filename":file_name}
                    result=metadata.find(query, {"_id":0, "peerId":1, "peerPort":1, "orderInFile":1, "piecehash":1, "piecesize":1, "filename":1})
                    conn.send(dumps(list(result)).encode(FORMAT))
                else:
                    conn.send("[ERROR] Not found message!".encode(FORMAT))
                    break
                print(f"[{addr}] {msg}\n")
        except:
            connected=False
    conn.close()
    
def handle_admin_commands():
    while True:
        command = input("Server Command: ")
        if command == "list":
            print("[ACTIVE CONNECTIONS] Active peers:")
            for t in threading.enumerate():
                if t.name.startswith('Peer'):
                    print(f"- {t.name}")
        
        elif command == "clear":
            metadata.delete_many({})
            print("[ADMIN] Cleared all data from database.")
        
        elif command.startswith("show peers"):
            try:
                file_name = command.split()[2]
                print(file_name)
                query = {"filename": file_name}
                result = metadata.find(query, {"_id": 0, "peerId": 1, "peerPort": 1, "orderInFile": 1})
                print("[ADMIN] Peer data:")
                for doc in result:
                    print(doc)
            except ValueError:
                print("[ERROR] Usage: show peers <file_name>")
        
        elif command == "shutdown":
            print("[ADMIN] Shutting down server...")
            server.close()
            break
        
        else:
            print("[ERROR] Unknown command.")
def start():
    try:
        server.listen()
        print(f"[LISTENING] on  {SERVER}")
        admin_thread = threading.Thread(target=handle_admin_commands, name="AdminThread")
        admin_thread.daemon = True  # Allow program to exit even if admin thread is running
        admin_thread.start()

        while True:
            conn, addr=server.accept()
            thread=threading.Thread(target=handle_client,args=(conn,addr),name=f"Peer {addr}")
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {len([t for t in threading.enumerate() if t.name.startswith('Peer')])}")
    except Exception as e:
        print(f"[ERROR] Server error: {e}")
    finally:
        server.close()
        print("[CLOSED] Server socket closed.")

print("[STARTING] server is starting...")
start()


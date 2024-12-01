# Import socket module 
import socket			 
import sys
import os
import hashfile as hfile
import splitfile as sfile
import json
import threading
import mergefile as mfile
import ast
PORT=5050
SERVER=('192.168.2.6')
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
    def __init__(self, peerId, peerPort, filename,filesize, piecehash, piecesize, orderInFile, totalpieces):
        self.peerId=peerId
        self.peerPort=peerPort
        self.filename=filename
        self.filesize=filesize
        self.piecehash=piecehash
        self.piecesize=piecesize
        self.orderInFile=orderInFile
        self.totalpieces=totalpieces

piecelist=[]
listfile=[]

def send(msg):
    message=msg.encode(FORMAT)
    msg_length=len(message)
    send_length=str(msg_length).encode(FORMAT)
    send_length+=b' '*(HEADER-len(send_length))
    client.send(send_length)
    client.send(message)
    return (client.recv(20480000).decode(FORMAT))

def obj_dict(obj):
    return obj.__dict__

def datastring(file_path):
    algorithm = "sha1"
    listfile=sfile.spiltfile(file_path)
    print(f'File {file_path} has {len(listfile)} pieces.')
    pieces=input(f'Please select pieces(s) to publish (Started at 0 or "all"): ').split()
    if (pieces[0]=="all"):
        for i in range(0, len(listfile)):
            try:
                file_hash = hfile.compute_file_hash(listfile[i], algorithm)
                piecelist.append(pieceInfo(IP, local_port, file_path, os.path.getsize(file_path), file_hash, os.path.getsize(listfile[i]),i, len(listfile)))
            except FileNotFoundError:
                print("File not found. Please enter a valid file path.")
    else:
        for i in range(0, len(pieces)):
            try:
                file_hash = hfile.compute_file_hash(listfile[int(pieces[i])], algorithm)
                piecelist.append(pieceInfo(IP, local_port, file_path, os.path.getsize(file_path), file_hash, os.path.getsize(listfile[int(pieces[i])]),int(pieces[i]),len(listfile)))
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
                conn.send(DISCONNECT_MESSAGE)
                conn.close()
                break
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
                        connection_semaphore.release()
                        connected=False
                        break
                    else:
                        cmand=msg.split(' + ')[0]   
                        if cmand=="request":
                            if len(piecelist)==0:
                                conn.send(f"[ERROR] No such file found!".encode(FORMAT))
                                continue

                            file_info=json.loads(msg.split(' + ')[1])
                            
                            file_name=file_info.split()[0]
                            piece=file_info.split()[1]
                            piece_exist=[i for i in piecelist if i.filename==file_name and str(i.orderInFile)==piece]
                            if (len(piece_exist)==0):
                                conn.send(f"[ERROR] No such file found!".encode(FORMAT))
                                continue
                            hashinfo=json.loads((send("handshake + "+file_name)))    
                            result=[] 
                            for j in hashinfo:
                                if (j["peerId"]==IP and j["peerPort"]==local_port and j["filename"]==file_name and str(j["orderInFile"])==piece):   
                                    result.append(j)
                                    break
                            piece_name="chunk" + file_name + str(result[0]['orderInFile']) + ".txt"
                            with open(piece_name, "rb") as f:
                                    piece_data=f.read()
                                    conn.send(f"{result[0]['piecesize']}".encode(FORMAT))
                                    conn.sendall(piece_data)
                                    print(f"[SUCCESSFULLY] Piece {piece} sent!")
                        elif cmand=="merge":
                            filename=msg.split(' + ')[1]
                            hashinfo=json.loads((send("handshake + "+filename))) 
                            total_piece=hashinfo[0]['totalpieces']
                            merge=False
                            for i in range(total_piece):
                                piece_name=f"received_chunk{filename}{i}.txt"
                                merge=os.path.isfile(piece_name)
                                if merge==False:
                                    conn.send("[ERROR] There aren't enough pieces to merge!".encode(FORMAT))
                                    print("[ERROR] There aren't enough pieces to merge!")
                                    break
                            if merge==True:
                                mfile.mergefile(filename,total_piece,524288)
                                conn.send(f"[MERGE FILE] {filename} successfully!".encode(FORMAT))
                        elif cmand=="send":
                            conn.send("[SEND RECEIVED]".encode(FORMAT))
                        else:
                            print("[ERROR] Unknown command.")

                    print(f'[RECEIVED MESSAGE] {msg}')
            except Exception as e:
                print(f"[ERROR] Peer communication error: {e}")
        
def send_peer(peer_socket, msg):
    message=msg.encode(FORMAT)
    msg_length=len(message)
    send_length=str(msg_length).encode(FORMAT)
    send_length+=b' '*(HEADER-len(send_length))
    peer_socket.send(send_length)
    peer_socket.send(message)
    return (peer_socket.recv(20480000).decode(FORMAT))

def verify(expected_hash,piece_name):
    piece_hash=hfile.compute_file_hash(piece_name, algorithm='sha1')
    return piece_hash==expected_hash

def handshake(command):
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
                if len(msg)>2:
                    for i in range(len(msg)):
                        if i+2==len(msg): 
                            break
                        message=str(msg[1])+" " +str(msg[i+2])
                        piece_size=(send_peer(peer_socket, "request + "+json.dumps(message)))
                        if not "[ERROR]" in piece_size:
                            piece_size=int(piece_size)
                                    # Read the actual piece data
                            piece_data = b""
                            while len(piece_data) < piece_size:
                                buffer = peer_socket.recv(min(1024, piece_size - len(piece_data)))
                                if not buffer:
                                    break
                                piece_data += buffer
                                    # Save the piece data to a file
                            piece_name = f"received_chunk{msg[1]}{msg[i + 2]}.txt"
                            infofile=json.loads((send("handshake + "+msg[1])))
                            result=[]
                            for j in infofile:
                                if (j["filename"]==msg[1] and str(j["orderInFile"])==msg[i+2]):   
                                    result.append(j)
                                    break
                            expected_hash=result[0]['piecehash']
                            with open(piece_name, "wb") as f:
                                f.write(piece_data)
                                if verify(expected_hash, piece_name):
                                    print(f"[SUCCESSFULLY] Received piece {i} and saved as {piece_name}")
                                else:
                                    print(f"[ERROR] Piece verification failed")
                                    break
                        else:
                            print(piece_size)
                else:
                    #Check out total piece of file
                    infofile=json.loads((send("handshake + "+msg[1])))
                    total_piece=infofile[0]['totalpieces']
                    piece_size=""
                    #Write file
                    for i in range(total_piece):
                        message=str(msg[1])+" " +str(i) 
                        piece_size=(send_peer(peer_socket, "request + "+json.dumps(message)))
                        if not "[ERROR]" in piece_size:
                            piece_size=int(piece_size)
                                    # Read the actual piece data
                            piece_data = b""
                            while len(piece_data) < piece_size:
                                buffer = peer_socket.recv(min(1024, piece_size - len(piece_data)))
                                if not buffer:
                                    break
                                piece_data += buffer
                                    # Save the piece data to a file
                            piece_name = f"received_chunk{msg[1]}{i}.txt"
                            infofile=json.loads((send("handshake + "+msg[1])))
                            result=[]
                            for j in infofile:
                                if (j["filename"]==msg[1] and str(j["orderInFile"])==str(i)):   
                                    result.append(j)
                                    break
                            expected_hash=result[0]['piecehash']
                            with open(piece_name, "wb") as f:
                                f.write(piece_data)
                                if verify(expected_hash, piece_name):
                                    print(f"[SUCCESSFULLY] Received piece {i} and saved as {piece_name}")
                                else:
                                    print(f"[ERROR] Piece verification failed")
                                    break
                        else:
                            print(piece_size)
                    #Merge file
                    merge=False
                    for i in range(total_piece):
                        merge=os.path.isfile(f"received_chunk{msg[1]}{i}.txt")
                    if merge==True:
                        mfile.mergefile(msg[1], total_piece, 524288)
            elif (msg[0]=="disconnect"):
                print(send_peer(peer_socket, DISCONNECT_MESSAGE))
                connected=False
                break
            elif (msg[0]=="merge"):
                print(send_peer(peer_socket, "merge + " +msg[1]))
            elif (msg[0]=="send"):
                print(send_peer(peer_socket, "send + " +msg[1]))
            else:
                print("[ERROR] Unknown command.")
        peer_socket.close() 
    except Exception as e:
        print(f"[ERROR] Handshake error: {e}")

def handshake_MDDT(peerid, peerport, filename, pieces):
    target_ip = peerid
    target_port = int(peerport)
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[PEER CONNECTING] to {target_ip}:{target_port}")
        peer_socket.connect((target_ip, target_port))
        print("[PEER CONNECTED] Successfully connected to peer.")
        # Send a test message
        for piece in (pieces):
            message=str(filename)+" " +str(piece)
            piece_size=(send_peer(peer_socket, "request + "+json.dumps(message)))
            if not "[ERROR]" in piece_size:
                print(piece_size)
                piece_size=int(piece_size)
                piece_data = b""
                while len(piece_data) < piece_size:
                    buffer = peer_socket.recv(min(1024, piece_size - len(piece_data)))
                    if not buffer:
                        break
                    piece_data += buffer                               
                piece_name = f"received_chunk{filename}{piece}.txt"
                infofile=json.loads((send("handshake + "+filename)))
                result=[]
                for j in infofile:
                    if (j["filename"]==filename and str(j["orderInFile"])==str(piece)):   
                        result.append(j)
                        break
                expected_hash=result[0]['piecehash']
                with open(piece_name, "wb") as f:
                    f.write(piece_data)
                    if verify(expected_hash, piece_name):
                        print(f"[SUCCESSFULLY] Received piece {piece} and saved as {piece_name} at {target_ip}:{target_port}")
                    else:
                        print(f"[ERROR] Piece verification failed")
                        break
            else:
                print(piece_size)
        
        
        peer_socket.close() 
    except Exception as e:
        print(f"[ERROR] Handshake error: {e}")

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
            peers=json.loads(send('peers + '+command[1]))
            for peer in peers:
                print(peer)
            if (len(peers)==0):
                print("[MESSAGE] There's no peers owning this file!")
        elif command[0]=="handshake":
            handshake(command[1])
        elif command[0]=="list":
            print('[ACTIVE PEERS]')
            print(send('list + list'))
        elif command[0] == "mddt":
            class peer_object:
                def __init__(self, peerIp, peerPort):
                    self.peerIp=peerIp
                    self.peerPort=peerPort
            peers=[]

            listpeers = json.loads((send('list + list')))
            tmp=json.loads(send("peers + "+command[1]))
            total_piece=(tmp[0]["totalpieces"])
            pieces_arr=list(range(0,int(total_piece)))
            pieces=[]
            for i in tmp:
                if i["peerId"]==IP and i["peerPort"]==local_port:
                    pieces_arr.remove(i["orderInFile"])
            for i in listpeers:
                tmpiece=[]
                if (len(pieces_arr)==0):
                    break
                if (len(peers)>5):
                    break
                i=ast.literal_eval(i.replace("Peer", ""))
                ip, port=i
                if (ip==IP and port==local_port):
                    continue
                for j in tmp:
                    if j["peerId"]==ip and j["peerPort"]==port and j["orderInFile"] in pieces_arr:
                        tmpiece.append(j["orderInFile"])
                        pieces_arr.remove(j["orderInFile"])
                pieces.append(tmpiece)
                peers.append(peer_object(ip, port))

            threads = []
            for i in range(len(peers)):
                t = threading.Thread(
                    target=handshake_MDDT, args=(peers[i].peerIp, peers[i].peerPort, command[1], pieces[i])
                )
                threads.append(t)
                t.start()
                if (i==len(peers)-1):
                    mfile.mergefile(command[1], total_piece, 524288)

            

            for t in threads:
                t.join()
            print("[MDDT COMPLETED]")
        else:
            print("[ERROR] Unknown command.")
        command=input().split()

main()
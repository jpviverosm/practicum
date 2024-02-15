from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, socket
from threading import Thread
import json
import time
import os

def incomming_connections():

    while True:

        client, addr = SERVER.accept()
        print(f'A client has connected {addr}')
        Thread(target=single_client, args=(client,addr)).start()

def single_client(client,addr):
    clients[addr] = client

    while True:
        msg = client.recv(BUFFERSIZE)                
        msg_json = json.loads(msg)

        if msg_json['net_action'] == 'online()':            
            real_clients_num, real_clients_name = get_clients()

            payload = {
                'net_action': 'confirm_list',
                'real_clients_num': real_clients_num,
                'real_clients_name': real_clients_name 
            }

            unicast_msg(payload, client)


        elif msg_json['net_action'] == 'name()': 
            new_client_name = msg_json['name']
            clients[new_client_name] = clients.pop(addr)
            print("Nodes: {}".format(clients))

            payload = {
                'net_action': 'confirm_name',
                'name': new_client_name,
                'file': False
            }

            unicast_msg(payload, client)

            time.sleep(1)

            payload_b = {
                'net_action': 'new_node',
                'client_name': new_client_name,
                'file': False
            }

            broadcast_msg(payload_b)
            
        elif msg_json['net_action'] == 'exit()':
            client_name = msg_json['name']
            print(f'{client_name} has disconnected ')
            client.close()
            clients.pop(client_name)

            print("Nodes: {}".format(clients))

            payload = {
                'net_action': 'confirm_exit',
                'client_leaving': client_name
            }

            broadcast_msg(payload)
            break

        elif msg_json['net_action'] == 'unicast()':
            destination = msg_json['destination']
            if msg_json['file'] == True:
                recvfile(client,msg_json['filename'])
             
            unicast_msg(msg_json, clients[destination])

        elif msg_json['net_action'] == 'broadcast()':
            if msg_json['file'] == True:
                recvfile(client, msg_json['filename'])

            broadcast_msg(msg_json)

def recvfile(client,filename):
    filename = os.path.basename(filename)
    with open(filename, "wb") as f:
        while True:
            # read 1024 bytes from the socket (receive)
            bytes_read = client.recv(BUFFERSIZE)
            if not bytes_read:    
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            f.write(bytes_read)

def sendfile(client,filename):
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(BUFFERSIZE)
            if not bytes_read:
                # file transmitting is done
                break
            # we use sendall to assure transimission in 
            # busy networks
            client.sendall(bytes_read)


def broadcast_msg(msg_json):
    client_msg = json.dumps(msg_json)

    for client in clients.values():
        client.send(client_msg.encode('utf-8'))


def unicast_msg(msg_json, client):   
    client_msg = json.dumps(msg_json)
    client.send(client_msg.encode('utf-8'))

    if msg_json['file'] == True:
        sendfile(client, msg_json['filename'])

def get_clients():
    real_clients_num = 0
    real_clients_name = []

    for k,v in clients.items():
        if k != 'Annonymous':
            real_clients_num += 1
            real_clients_name.append(k)

    return real_clients_num, real_clients_name


if __name__ == "__main__":

    clients = {}

    HOST = '127.0.0.1'
    PORT = 33336
    BUFFERSIZE = 1024
    ADDR = (HOST, PORT)
    EXIT_CMD = "exit()"
    NAME_CMD = "name()"
    SERVER = socket(AF_INET, SOCK_STREAM)
    SERVER.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    SERVER.bind(ADDR)
    SERVER.listen(10)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=incomming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
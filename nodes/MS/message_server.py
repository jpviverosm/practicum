from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, socket
from threading import Thread
import json
import time
import os

class Node:
    def __init__(self, name, addr):
        self.name = name
        self.addr = addr
        self.isValidator = False
        self.isRequestor = False
        self.isClient = False



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
                'real_clients_name': real_clients_name,
                'validators': validators_list,
                'file': False 
            }

            unicast_msg(payload, client)


        elif msg_json['net_action'] == 'name()': 
            new_client_name = msg_json['name']
            clients[new_client_name] = clients.pop(addr)

            node = Node(new_client_name, addr)
            nodes.append(node)

            print("Nodes: {}".format(clients))
            bcaction = ''
            is_validator = False

            #if msg_json['bcaction'] == 'add_validator':
            #    bcaction = 'add_validator'

            payload = {
                'net_action': 'confirm_name',
                'name': new_client_name,
                'file': False
            }

            unicast_msg(payload, client)

            time.sleep(0.2)

            if msg_json['validator'] == True:
                node.isValidator = True
                is_validator = True
                validators_list.append(new_client_name)

            payload_b = {
                'net_action': 'new_node',
                'validator': is_validator,
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
                'client_leaving': client_name,
                'file': False
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
    fd = open(filename, "wb")

    # read 1024 bytes from the socket (receive)
    #bytes_read = client.recv(BUFFERSIZE)
    #print(bytes_read)
    done = False
    file_bytes = b""
    while not done:
        print('control test')
        bytes_read = client.recv(BUFFERSIZE)
        #print('bytes read: {}'.format(bytes_read))
        print('terminate signal: {}'.format(bytes_read[-2:]))
        #print('file bytes: {}'.format(file_bytes))
        file_bytes += bytes_read
        if bytes_read[-2:] == b"<>":
            done = True
            print('tranmission complete')
        else:
            #file_bytes += bytes_read
            print('receiving data...')
    file_bytes = file_bytes[:-2]
    print(file_bytes)
    fd.write(file_bytes)
        #else:
        #    # write to the file the bytes we just received
        #    print('receiving data...')
        #    fd.write(bytes_read)
        #    bytes_read = client.recv(BUFFERSIZE)
    print('closing file')
    fd.close()


def sendfile(client,filename):
    fd = open(filename, "rb")
    while True:
        # read the bytes from the file
        bytes_read = fd.read()
        if not bytes_read:
            # file transmitting is done
            print('file completely read')
            break
        while bytes_read:
            # we use sendall to assure transimission in 
            # busy networks
            print('sending data...')
            client.sendall(bytes_read)
            bytes_read = fd.read()
    print('closing file')
    fd.close()
    client.send(bytes("<>", "utf-8"))


def broadcast_msg(msg_json):
    client_msg = json.dumps(msg_json)

    for client in clients.values():
        client.send(client_msg.encode('utf-8'))

        if msg_json['file'] == True:
            time.sleep(2)
            sendfile(client, msg_json['filename'])


def unicast_msg(msg_json, client):   
    client_msg = json.dumps(msg_json)
    client.send(client_msg.encode('utf-8'))

    if msg_json['file'] == True:
        time.sleep(0.5)
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
    nodes = []
    validators_list = []

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
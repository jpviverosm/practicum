from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, socket
from threading import Thread
import json
import time

def incomming_connections():

    while True:

        client, addr = SERVER.accept()
        print(f'A client has connected {addr}')
        #Thread(target=single_client, args=(client,)).start()
        Thread(target=single_client, args=(client,addr)).start()

def single_client(client,addr):

    #client_name = 'Anonymous'
    #clients[client] = client_name

    clients[addr] = client

    #clients[client_name] = client

    while True:
        msg = client.recv(BUFFERSIZE)
        msg_json = json.loads(msg)

        if msg_json['net_action'] == 'online()':            
            real_clients_num, real_clients_name = get_clients()

            #real_clients_name, real_clients_num = get_clients()

            payload = {
                'net_action': 'confirm_list',
                'real_clients_num': real_clients_num,
                'real_clients_name': real_clients_name 
            }

            unicast_msg(payload, client)

        elif msg_json['net_action'] == 'name()': 
            new_client_name = msg_json['name']
            #clients[client] = new_client_name

            clients[new_client_name] = clients.pop(addr)
            print("Nodes: {}".format(clients))

            payload = {
                'net_action': 'confirm_name',
                'name': new_client_name
            }

            #print('client for unicast message: {}'.format(client))
            unicast_msg(payload, client)

            time.sleep(1)

            payload_b = {
                'net_action': 'new_node',
                'client_name': new_client_name
            }

            broadcast_msg(payload_b)
            
        elif msg_json['net_action'] == 'exit()':
            client_name = msg_json['name']
            #print(f'{clients[client]} has disconnected ')
            print(f'{client_name} has disconnected ')
            client.close()
            #client_leaving = clients[client]
            #del clients[client]

            #client_leaving = clients[client_name]
            clients.pop(client_name)

            print("Nodes: {}".format(clients))

            payload = {
                'net_action': 'confirm_exit',
                'client_leaving': client_name
            }

            broadcast_msg(payload)
            #client.close()
            break

        elif msg_json['net_action'] == 'unicast()':
            #msg_json['net_action']
            destination = msg_json['destination']
            #print(clients.keys())
            #print(clients.values())
            unicast_msg(msg_json, clients[destination])

        elif msg_json['net_action'] == 'broadcast()':
            broadcast_msg(msg_json)


def broadcast_msg(msg):
    client_msg = json.dumps(msg)
    #for client in clients:
    #    client.send(client_msg.encode('utf-8'))

    for client in clients.values():
        client.send(client_msg.encode('utf-8'))


def unicast_msg(msg, client):
    client_msg = json.dumps(msg)
    #print('unicast message: {}'.format(client_msg))
    client.send(client_msg.encode('utf-8'))

def get_clients():
    
    real_clients_num = 0
    real_clients_name = []

    for k,v in clients.items():
        #if v != 'Annonymous':
        #    real_clients_num += 1
        #    real_clients_name.append(v)

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
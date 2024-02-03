from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from signal import signal, SIGINT
import sys
import os
import json
import time

def receive_msg():
    while True:
    #while not EXIT:
        if EXIT:
            break
        try:
            msg = client_socket.recv(BUFFERSIZE)
            msg_json = json.loads(msg)

            if msg_json['net_action'] == 'confirm_name':
                print('Name: {}'.format(msg_json['name']))

            elif msg_json['net_action'] == 'new_node':
                print('{} has joined the network'.format(msg_json['client_name']))


            elif msg_json['net_action'] == 'confirm_list':
                BCNETWORKNUM = msg_json['real_clients_num']
                BCNETWORKNODES = msg_json['real_clients_name']

                #print(BCNETWORKNUM)
                print(BCNETWORKNODES)

            elif msg_json['net_action'] == 'confirm_exit':
                print('{} has left the network'.format(msg_json['client_leaving']))

            elif msg_json['net_action'] == 'unicast()':
                print(msg_json)
                if msg_json['file'] == True:
                    recvfile(msg_json['filename'])

            elif msg_json['net_action'] == 'broadcast()':
                print(msg_json)
                if msg_json['file'] == True:
                    recvfile(msg_json['filename'])

        except OSError as error:
            return error
        
def recvfile(filename):
    filename = os.path.basename(filename)
    fd = open(filename, "wb")
    while True:
        # read 1024 bytes from the socket (receive)
        bytes_read = client_socket.recv(BUFFERSIZE)
        if not bytes_read:    
            # nothing is received
            # file transmitting is done
            break
        else:
            # write to the file the bytes we just received
            fd.write(bytes_read)
    fd.close()

    '''
    with open(filename, "wb") as f:
        while True:
            # read 1024 bytes from the socket (receive)
            bytes_read = client_socket.recv(BUFFERSIZE)
            if not bytes_read:    
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            f.write(bytes_read)
    '''

def sendfile(filename):
    fd = open(filename, "rb")
    while True:
        # read the bytes from the file
        bytes_read = fd.read()
        print(bytes_read)
        if not bytes_read:
            # file transmitting is done
            print('file completely read')
            break
        while bytes_read:
            # we use sendall to assure transimission in 
            # busy networks
            print('sending data...')
            client_socket.sendall(bytes_read)
            bytes_read = fd.read()
    print('closing file')
    fd.close()
    client_socket.send(bytes("<>", "utf-8"))

    '''
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(BUFFERSIZE)
            if not bytes_read:
                # file transmitting is done
                break
            # we use sendall to assure transimission in 
            # busy networks
            client_socket.sendall(bytes_read)
    '''

def send_msg(payload):
    try:
        msg = json.dumps(payload)
        client_socket.send(msg.encode('utf8'))
    except EOFError:
        clean_exit()

def clean_exit():
    payload = {
        'net_action': 'exit()',
        'name': NAME
    }
    send_msg(payload)
    client_socket.close()
    EXIT = True
    sys.exit(0)

def handler(signal_recv, frame):
    clean_exit()

def unicast(destination, message = '', filename = ''):
    fileflag = False
    if filename != '':
        fileflag = True
    payload = {
        'net_action': 'unicast()',
        'file': fileflag,
        'filename': filename,
        'destination': destination,
        'message': message
    }

    send_msg(payload)
    if fileflag:
        time.sleep(0.5)
        sendfile(filename)

def broadcast():
    payload = {
        'net_action': 'broadcast()',
        'message': 'test_requestor1'
    }

    send_msg(payload)

def network():
    payload = {
        'net_action': 'online()',
    }

    send_msg(payload)

def name(name):
    payload = {
        'net_action': 'name()',
        'file': False,
        'name': name
    }

    send_msg(payload)

def menu():
    selected = 0
    #exit = False

    while not EXIT:
        time.sleep(0.3)
        print("\n1. Unicast.\n2. Broadcast.\n3. Network.\n4. Exit")
        selected = input("Selected option: ")
        if int(selected) == 1:
            #print("Available nodes: ")
            #network()
            dest = input("\nType destination node: ")
            file = input("\nSend file? Y/N: ")
            if file == "Y":
                #unicast(dest, 'test', 'test.pem')
                unicast(dest, 'test', 'test_req1.txt')
            else:
                unicast(dest, 'test')
        if int(selected) == 2:
            print("\nBroadcasting")
            broadcast()
        if int(selected) == 3:
            network()
        if int(selected) == 4:
            clean_exit()


        #else:
        #    print("\nSelect a valid option:")
            


if __name__ == '__main__':
    signal(SIGINT, handler)
    HOST = '127.0.0.1'
    PORT = 33336
    BUFFERSIZE = 1024
    ADDR = (HOST, PORT)
    ACTION = ''
    NAME = 'Requestor1'
    BCNETWORKNUM = 0
    BCNETWORKNODES = []
    EXIT = False
    PAYLOAD = {
        'action': '',
        'file': False,
        'name': NAME
    }

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(ADDR)
    receive_thread = Thread(target=receive_msg)
    receive_thread.start()

    # set name 
    #PAYLOAD['net_action'] = 'name()'
    #send_msg(PAYLOAD)
    name(NAME)

    time.sleep(1)

    menu()

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

            elif msg_json['net_action'] == 'broadcast()':
                print(msg_json)

        except OSError as error:
            return error
        
def send_msg(payload):
    #while True:
    #    try:
    #        msg = input()
    #        if msg != 'exit()':
    #            client_socket.send(msg.encode('utf8'))
    #        else:
    #            clean_exit()
    #    except EOFError:
    #        clean_exit()

    try:
        #if msg != 'exit()':
        #if payload['net_action'] != 'exit()':
        #    msg = json.dumps(payload)
        #    client_socket.send(msg.encode('utf8'))
        #else:
        #    clean_exit()
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
    #receive_thread.stop()
    sys.exit(0)

def handler(signal_recv, frame):
    clean_exit()

def unicast(destination):
      payload = {
            'net_action': 'unicast()',
            'destination': destination,
            'message': 'test_validator1'
      }

      send_msg(payload)

def broadcast():
      payload = {
            'net_action': 'broadcast()',
            'message': 'test_validator1'
      }

      send_msg(payload)

def network():
      payload = {
            'net_action': 'online()',
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
            dest = input("\nType destination node: ")
            unicast(dest)
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
    NAME = 'Validator1'
    BCNETWORKNUM = 0
    BCNETWORKNODES = []
    EXIT = False
    PAYLOAD = {
        'action': '',
        'name': NAME
    }

    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(ADDR)
    receive_thread = Thread(target=receive_msg)
    receive_thread.start()

    # set name 
    PAYLOAD['net_action'] = 'name()'
    send_msg(PAYLOAD)

    time.sleep(1)

    menu()

#    if ACTION == 'CertReq':
#        send_msg('Certificate')
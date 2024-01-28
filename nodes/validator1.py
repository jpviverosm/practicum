from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from signal import signal, SIGINT
import sys
import os
import json

def receive_msg():
    while True:
        try:
            #msg = client_socket.recv(BUFFERSIZE).decode("utf8")
            msg = client_socket.recv(BUFFERSIZE)
            #print(type(client_socket))
            #print(msg)
            #print(type(msg))
            msg_json = json.loads(msg)

            if msg_json['net_action'] == 'confirm_name':
                print('Name: {}'.format(msg_json['name']))
                #print(type(msg_json))
            elif msg_json['net_action'] == 'confirm_list':
                BCNETWORKNUM = msg_json['real_clients_num']
                BCNETWORKNODES = msg_json['real_clients_name']

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
        if payload['net_action'] != 'exit()':
            msg = json.dumps(payload)
            client_socket.send(msg.encode('utf8'))
        else:
            clean_exit()
    except EOFError:
        clean_exit()

def clean_exit():
    client_socket.send('exit()'.encode('utf8'))
    client_socket.close()
    sys.exit(0)

def handler(signal_recv, frame):
    clean_exit()

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

#    if ACTION == 'CertReq':
#        send_msg('Certificate')
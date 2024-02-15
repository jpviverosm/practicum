import socket
import threading
import time


def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 6000  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together
    print("socket binded to {}".format(port)) 

    # configure how many client the server can listen simultaneously
    server_socket.listen(5)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024).decode()
        if not data:
            # if data is not received break
            break
        print("from connected user: " + str(data))
        #data = input(' -> ')

        response = 'received'
        conn.send(response.encode())  # send data to the client

    conn.close()  # close the connection

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    #message = input(" -> ")  # take input

    message = 'test_client'

    #while message.lower().strip() != 'bye':
    #    client_socket.send(message.encode())  # send message
    #    data = client_socket.recv(1024).decode()  # receive response
    #    print('Received from server: ' + data)  # show in terminal

    #    message = input(" -> ")  # again take input

    client_socket.send(message.encode())  # send message
    data = client_socket.recv(1024).decode()  # receive response

    print('Received from server: ' + data)  # show in terminal


    #client_socket.close()  # close the connection


if __name__ == '__main__':
    server_thread = threading.Thread(target=server_program())

    client_thread = threading.Thread(target=client_program())

    #server_thread.start()
    #time.sleep(1)
    client_thread.start()
    server_thread.start()
    #server_program()
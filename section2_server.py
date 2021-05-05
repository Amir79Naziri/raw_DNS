import socket
import threading


def clientHandler(connection, message, address, ID):
    message = "Message from Client-{}: ".format(ID) + bytes.decode(message)
    adr_msg = "Client-{} Address: ".format(ID) + str(address)

    print(message)
    print(adr_msg)

    try:
        connection.sendto(str.encode('done'), address)
    except ConnectionError as msg_:
        print(msg_)
        return
    except IOError as msg_:
        print(msg_)
        return


if __name__ == '__main__':
    serverSocket = None
    counter = 1
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverSocket.bind(('127.0.0.1', 8080))
        print('Server started')

        while True:
            data = serverSocket.recvfrom(1024)
            print('Client-{} accepted'.format(counter))
            threading.Thread(target=clientHandler,
                             args=(serverSocket, data[0], data[1], counter)).start()
            counter += 1


    except ConnectionError as msg:
        print(msg)
    except IOError as msg:
        print(msg)
    finally:
        serverSocket.close()

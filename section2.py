import socket

if __name__ == '__main__':
    address = ("127.0.0.1", 8080)

    clientSocket = None
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSocket.settimeout(10)

        clientSocket.sendto(str.encode(input('Message: ')), address)
        mg = clientSocket.recvfrom(1024)
        mg = bytes.decode(mg[0])
        print(mg)

    except ConnectionError as msg:
        print(msg)
    except IOError as msg:
        print(msg)
    finally:
        clientSocket.close()

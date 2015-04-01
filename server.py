# Network Security Spring 2015 Assignment 2
# Programming problem
# Roberto Amorim - rja2139

import argparse, socket, signal
import time, ssl, os.path
from threading import Thread

# Configuration variables
BUFSIZE = 1024
filename = ""

# Here I take care of the command line arguments
parser = argparse.ArgumentParser(description='Server that holds encrypted files.', add_help=True)

parser.add_argument('--port', dest = 'port', required = True, help='Server Port')
parser.add_argument('--cert', dest = 'cert', required = True, help = 'Server certificate')
parser.add_argument('--key', dest = 'key', required = True, help = 'Server certificate key')

args = parser.parse_args()

# Here I validate the server port
if args.port.isdigit():
    port = int(args.port)
    if port > 65535:
        print "ERROR: The port number is outside the acceptable range! (0-65535)"
        exit(1)
else:
    print "ERROR: The server port must be a number!"
    exit(1)

# Here I validate the filenames
if not os.path.isfile(args.cert):
    print "ERROR: Invalid file name for certificate"
    exit(1)

if not os.path.isfile(args.key):
    print "ERROR: Invalid file name certificate key"
    exit(1)


def serverthread(ssl_sock, clientaddr):
    global filename
    receive = ssl_sock.recv(BUFSIZE)
    data = receive.split(' ', 1)
    if data[0] == "NAME":
        filename = data[1]
    elif data[0] == "FILE":
        file = open("server" + os.sep + filename, "wb")
        file.write(data[1])
        while True:
            data = ssl_sock.recv(BUFSIZE)
            if not data: # Until data stops arriving
                print "File arrived from client"
                break
            file.write(data)
        file.close()
    elif data[0] == "HASH":
        file = open("server" + os.sep + filename + ".sha256", "wb")
        file.write(data[1])
        file.close()
    elif data[0] == "GET":
        try:
            with open("server" + os.sep + data[1], 'rb') as f:
                contents = f.read()
        except:
            ssl_sock.write("FILEERROR")
            return
        f.close()
        with open("server" + os.sep + data[1] + ".sha256", 'rb') as f:
            sha = f.read()
        f.close()
        ssl_sock.write(sha + contents)
    else:
        print "Unrecognized message. Something is very wrong"
    ssl_sock.close()


serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
def server():
    try:
        serversocket.bind(("0.0.0.0", port))
    except:
        print "Can't bind. Maybe port is already in use?"
        os._exit(0)
    serversocket.listen(5)
    while True:
        clientsock, clientaddr = serversocket.accept()
        ssl_sock = ssl.wrap_socket(clientsock,
                                   keyfile = args.key,
                                   certfile = args.cert,
                                   server_side = True,
                                   # Require the client to provide a certificate
                                   cert_reqs = ssl.CERT_REQUIRED,
                                   ca_certs = "ca.crt",   # must point to a file of CA certificates??
                                   do_handshake_on_connect = True,
                                   ciphers="!NULL:!EXPORT:AES256-SHA")
        clientthread = Thread(target=serverthread, args=(ssl_sock, clientaddr))
        clientthread.start()


# Main function, starts the server thread
def main():
    clientservthread = Thread(target=server)
    clientservthread.start()


# Signal handler that catches Ctrl-C and closes sockets before exiting
def handler(signum, frame):
    print "Quitting: Signal handler called with signal " + str(signum)
    serversocket.close()
    os._exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, handler)
    main()
    # If I let the main thread finish, it stops listening for signals
    while True:
        time.sleep(1)

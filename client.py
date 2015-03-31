# Network Security Spring 2015 Assignment 2
# Programming problem
# Roberto Amorim - rja2139

import argparse
import socket
import os.path
import ssl
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random


# Here I take care of the command line arguments
parser = argparse.ArgumentParser(description='Encrypts a file and sends it to a server.', add_help=True)

parser.add_argument('--server', dest = 'serverIP', required = True, help = 'Server IP Address')
parser.add_argument('--port', dest = 'serverPort', required = True, help='Server Port')
parser.add_argument('--cert', dest = 'cert', required = True, help = 'Client certificate')
parser.add_argument('--key', dest = 'key', required = True, help = 'Client certificate key')

args = parser.parse_args()

# Here I validate the IP address
try:
    socket.inet_aton(args.serverIP)
except socket.error:
    print "ERROR: The IP address you provided (" + args.serverIP + ") doesn't seem to be valid!"
    exit(1)

# Here I validate the server port
if args.serverPort.isdigit():
    port = int(args.serverPort)
    if port > 65535:
        print "ERROR: The port number is outside the acceptable range! (0-65535)"
        exit(1)
else:
    print "ERROR: The server port must be a number!"
    exit (1)

# Here I validate the filenames
if not os.path.isfile(args.cert):
    print "ERROR: Invalid file name for certificate"
    exit(1)

if not os.path.isfile(args.key):
    print "ERROR: Invalid file name certificate key"
    exit(1)


def send(data):
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        clientsock.connect((args.ip, port))
        clientsock.send(data)
    except:
        print "Error connecting to the remote server. Guess it went offline"
        os._exit(0)
    # Connections must NEVER be persistent!
    clientsock.close()


def cleanandexit():
    os._exit(0)


# The main program prompt
def prompt():
    try:
        text = raw_input('> ')
    except KeyboardInterrupt:
        print "Caught interrupt. Exiting..."
        cleanandexit()
    text = text.lstrip()
    command = text.split(' ', 1)

    if command[0] == "get":
        send("MESG " + command[1])
    elif command[0] == "put":
        send("BCST " + command[1])
    elif command[0] == "stop":
        cleanandexit()
    elif not command[0]:
        prompt()
    else:
        print "*** I could not understand the command you gave me. Valid commands are: ***"
        print "*** get, put, stop ***"

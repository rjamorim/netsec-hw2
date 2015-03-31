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


def readfile(filename):
    if not os.path.isfile(filename):
        print "ERROR: Invalid file name for transfer"
        prompt()
    else:
        try:
            with open(filename, 'rb') as f:
                plaintext = f.read()
        except IOError:
            print "ERROR: File can not be read! You must provide a file for which you have read permissions"
            prompt()
        f.close()
    return plaintext


def sha256(plaintext):
    hashed = SHA256.new()
    hashed.update(plaintext)
    print hashed.digest()
    return hashed.digest()


## A routine to pad the message so that its size becomes a multiple of block_size
def pad(message):
    padding = AES.block_size - (len(message) % AES.block_size)
    if padding == 0:
        padding = AES.block_size
    # Padding according to PKCS7:
    pad = chr(padding)
    return message + (pad * padding)


def encrypt(message, pwd, key_size=256):
    message = pad(message)
    # I create a random initialization vector the same length of the AES block size
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(pwd, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def send(data):
    clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(clientsock,
                               keyfile = args.key,
                               certfile = args.cert,
                               server_side = False,
                               cert_reqs = ssl.CERT_REQUIRED,
                               ca_certs = "ca.crt",
                               do_handshake_on_connect = True,
                               ciphers="!NULL:!EXPORT:AES256-SHA")
    #try:
    ssl_sock.connect((args.serverIP, port))
    ssl_sock.write(data)
    #except:
    #    print "Error connecting to the remote server. Guess it went offline"
    #    os._exit(0)
    ssl_sock.close()


def put(data):
    toks = data.split(' ')
    filename = toks[0]
    # First we read the filename
    plaintext = readfile(filename)
    #Now we compute the hash
    hash = sha256(plaintext)
    flag = toks[1] or "X"
    if flag == "N":
        # What we do in case no encryption is applied
        # First we send the filename
        send("NAME " + filename)
        send("FILE " + plaintext)
        send("HASH " + hash)
        print "bogus"
    elif flag == "E":
        pwd = toks[2] or "X"
        if len(pwd) != 8:
            print "The encryption password must be exactly 8 characters long"
            prompt()
        ciphertext = encrypt(plaintext, pwd)
        print "bogus"
    else:
        print "You must use a flag N or E after the filename!"
        prompt()


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
        put(command[1])
    elif command[0] == "stop":
        cleanandexit()
    elif not command[0]:
        prompt()
    else:
        print "*** I could not understand the command you gave me. Valid commands are: ***"
        print "*** get, put, stop ***"
        prompt()

prompt()
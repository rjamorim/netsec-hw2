# Network Security Spring 2015 Assignment 2
# Programming problem
# Roberto Amorim - rja2139


Worth mentioning: I didn't understand the requirement to "use the password as a seed to a random number
generator (RNG) to create a 16-byte AES key". With all random number generators I tried, I couldn't get
the same random numbers twice even when seeding with the password (which kinda makes sense, but then I
couldn't figure out how to use it as a key)
>>> import random
>>> random.seed("12345678")
>>> random.getrandbits(256)
113375236562917801394135310793316654021177578986871332423131375717599556609195
>>> random.getrandbits(256)
48319146521200183419876803542516434786490999973139087309506329081626584170840
>>> random.getrandbits(256)
16666249916440497156396344364859723184434647043037778913815173641634172511283
>>> random.seed("12345678")
>>> random.getrandbits(256)
109789581452087138186337105905770168215286731297098568234814127055506472004460

So, I used another method that seems well accepted to generate the encryption keys: hash repeatedly the
password several times (I settled at 100), each time adding a salt. The mix of dozens of rounds of
hashing, mixed with a strong salt (128 bits) allows the system to defeat password cracking schemes such
as rainbow tables, as it would be unfeasible to compute a hash table both time-wise and space-wise.


RUNNING THE PROGRAMS
python server.py --port 2663 --cert server.crt --key server.key
python client.py --server 127.0.0.1 --port 2663 --cert client.crt --key client.key

GENERATING THE CERTIFICATES
This is the command sequence to generate the certificates:

openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 1826 -key ca.key -out ca.crt

openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 730 -sha256 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 730 -sha256 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt

REFERENCES
http://blog.didierstevens.com/2008/12/30/howto-make-your-own-cert-with-openssl/
https://docs.python.org/dev/library/ssl.html
https://www.dlitz.net/software/pycrypto/api/2.4/
http://www.floyd.ch/?p=293
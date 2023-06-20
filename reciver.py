import random
import sys
sys.path.append("C:\\Users\\91798\\PycharmProjects\\pythonProject\\venv\\Lib\\site-packages")
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Cipher import CAST
#from os import urandom
from Crypto.Util.Padding import unpad
from base64 import b64decode
import blowfish
from base64 import b64encode
#from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
#from binascii import a2b_hex
import csv
import socket

# next create a socket object
s = socket.socket()
print("Socket successfully created")

# reserve a port on your computer in our
# case it is 12345 but it can be anything
port = 12345

# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.bind(('', port))
print("socket binded to %s" % (port))

# put the socket into listening mode
s.listen(5)
print("socket is listening")


# a forever loop until we interrupt it or
# an error occurs

# Assigning Algorithms Numbers :-
# 0 -> RSA
# 1 -> AES
# 2 -> TDES
# 3 -> BLOWFISH
# 4 -> CAST


'''def RSAdecryption(n, d, a):
    M = []
    for i in a:
        M.append(compute(int(i), d, n))
    print("Decrypted text is :-")
    plaintext = ""
    for i in M:
        plaintext += str(i)
    print("CW: ", plaintext[0:3])
    print("CARD NO. : ", plaintext[3:])'''


def compute(a, m, n):
    y = 1
    while (m > 0):
        r = m % 2
        if (r == 1):
            y = (y * a) % n
        a = a * a % n
        m = m // 2
    return y


def CASTdecryption(key, ciphertext, eiv):
    ciphertext = b64decode(ciphertext)
    eiv = b64decode(eiv)

    print("Decoded ciphertext : ", ciphertext, len(ciphertext))
    print("Decoded iv : ", eiv, len(eiv))
    cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)
    decryptedText = cipher.decrypt(ciphertext)

    print("Decrypted data is : ", decryptedText)
    print("CW: ", decryptedText[0:3])
    print("CARD NO. : ", decryptedText[3:])


def AESdecryption(key, ciphertext, iv):
    ciphertext = b64decode(ciphertext)
    iv = b64decode(iv)

    print("Decoded ciphertext : ", ciphertext, len(ciphertext))
    print("Decoded iv : ", iv, len(iv))
    # To decrypt, use key and iv to generate a new AES object
    mydecrypt = AES.new(key, AES.MODE_CBC, iv)

    # Use the newly generated AES object to decrypt the encrypted ciphertext
    decrypttext = unpad(mydecrypt.decrypt(ciphertext), AES.block_size)
    # decrypttext = mydecrypt.decrypt(ciphertext)
    print("The decrypted data is: ")
    print("CW: ", decrypttext[0:3])
    print("CARD NO. : ", decrypttext[3:])


def blowfishdecrypt(key, ciphertext, iv):
    ciphertext = b64decode(ciphertext)
    iv = b64decode(iv)

    print("Decoded ciphertext : ", ciphertext, len(ciphertext))
    print("Decoded iv : ", iv, len(iv))
    cipher = blowfish.Cipher(key)
    data_decrypted = b"".join(cipher.decrypt_cbc(ciphertext, iv))
    decrypttext = data_decrypted.decode()
    print("The decryped data is : ")
    print("CW: ", decrypttext[0:3])
    print("CARD NO. : ", decrypttext[3:])


def tripledesdecrypt(ciphertext, bkey):
    key = pad(bkey, 24)
    tdes_key = DES3.adjust_key_parity(key)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')
    ciphertext = b64decode(ciphertext)
    plaintext = cipher.decrypt(ciphertext)
    decrypttext = plaintext.decode('utf-8')
    print("Decrypted Text : ")
    print("CW: ", decrypttext[0:3])
    print("CARD NO. : ", decrypttext[3:])


def assymetricfinalkey(res):
    n = str(res[0])
    e = str(res[1])
    nsize = len(n)
    esize = len(e)
    print("ASSYMETRIC : n e nsize esize", n, e, nsize, esize)
    key = str(nsize) + n + str(esize) + e
    print("n = ", n)
    print("e = ", e)
    print("Key Format : algonumber + nsize + n + esize + e")
    return key


def randomize():
    rand = random.randint(40,4000)
    return (rand%5)


def check_prime(n):
    for i in range(2, n):
        if (n % i == 0):
            return 1
    return 0


def gcd(a, b):
    while (1):
        temp = a % b
        if temp == 0:
            return b
        a = b
        b = temp


def asymmetric():
    while (5):
        p = random.randint(1, 1000)
        while (check_prime(p) == 1):
            p = p + 1
        break
    while (5):
        q = random.randint(1, 1000)
        while (check_prime(q) == 1):
            q = q + 1
        break
    n = p * q
    phi_n = (p - 1) * (q - 1)
    while (5):
        e = random.randint(2, n - 1)
        if (gcd(e, phi_n) == 1):
            break
    k = 0
    while ((1 + (k * phi_n)) % e != 0):
        k += 1
    d = (1 + (k * phi_n)) // e

    res = [n, e, d]
    print("p = ", p)
    print("q = ", q)
    return res
    # print("n is",n)
    # print("e is",e)
    # print("d is",d)


algonumber = randomize()
if algonumber==0:
    exit(0)



else:
    bkey = get_random_bytes(16)
    key = str(algonumber)
    bkey1 = b64encode(bkey).decode('utf-8')
    key += bkey1

    keys = [key]
    with open('key.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)

        # write the data(cipher,iv)
        writer.writerow(keys)

        f.close()
    print("Symmetric Key : ", key)
    print("AlgoNumber : ", algonumber)
    while True:
        # Establish connection with client.
        c, addr = s.accept()
        # send a thank you message to the client. encoding to send byte type.
        c.send(key.encode())

        # Close the connection with the client
        #c.close()

        # Breaking once connection closed
        break

    if(algonumber==2 or algonumber==3):
        input(c.recv(1024))
    else:
        input(c.recv(1024).decode())
    with open("C:\\Users\\91798\\Desktop\\New folder\\sender\\ciphertext.csv") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if (len(row) == 0):
                break
            ciphertext = row[0]
            if algonumber != 2:
                iv = row[1]
        csv_file.close()
    c.close()

    if algonumber == 1:  # AES
        AESdecryption(bkey, ciphertext, iv)

    elif algonumber == 2:  # TDES
        tripledesdecrypt(ciphertext, bkey)
    elif algonumber == 4:  # CAST
        CASTdecryption(bkey, ciphertext, iv)
    elif algonumber == 3:  # Blowwfish
        blowfishdecrypt(bkey, ciphertext, iv)


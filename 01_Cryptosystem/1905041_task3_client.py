import importlib
import socket
import numpy as np

aes = importlib.import_module("1905041_aes")
cbc = importlib.import_module("1905041_cbc")
ecdh = importlib.import_module("1905041_ecdh")


# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print("Client Socket created successfully")

# Define the port on which you want to connect
port = 12345

# connect to the server on local computer
s.connect(('127.0.0.1', port))

incoming = s.recv(1024).decode()
if (incoming == "Connected Successfully"):
    s.send("ack conn".encode())

ec_p = s.recv(1024).decode()

Prime = int(ec_p)

if Prime != 0:
    s.send("ack prime".encode())
ec_a = s.recv(1024).decode()
ec_a = int(ec_a)
if ec_a != 0:
    s.send("ack a".encode())
ec_b = s.recv(1024).decode()
ec_b = int(ec_b)
if ec_b != 0:
    s.send("ack b".encode())
g_x = s.recv(1024).decode()
g_x = int(g_x)
if g_x != 0:
    s.send("ack G.x".encode())
g_y = s.recv(1024).decode()
g_y = int(g_y)
if g_y != 0:
    s.send("ack G.y".encode())
pub_x = s.recv(1024).decode()
pub_x = int(pub_x)
if pub_x != 0:
    s.send("ack Pub.x".encode())
pub_y = s.recv(1024).decode()
pub_y = int(pub_y)
if pub_y != 0:
    s.send("ack Pub.y".encode())

ecdh_worker = ecdh.ECDH_client(128)
ecdh_worker.curve = ecdh.EC(Prime, ec_a, ec_b)
ecdh_worker.gen_point =  ecdh.My_Point(g_x,g_y)

prv_key, public_key = ecdh_worker.mk_keys(ecdh_worker.curve, ecdh_worker.gen_point)

incoming = s.recv(1024).decode()

if (incoming == "give key"):
    s.send(str(public_key.x).encode())
incoming = s.recv(1024).decode()
if (incoming == "ack pubx"):
    s.send(str(public_key.y).encode())

shared_key = ecdh_worker.mk_shared_secret(ecdh.My_Point(pub_x, pub_y), prv_key)

# incoming = s.recv(1024).decode()
# s.send(str(shared_key.x).encode())

# if (incoming == str(shared_key.x)):
print("ECDH done")

msg = s.recv(1024).decode()

cbc_w=cbc.CBC()
key = np.zeros(int(128/8), dtype=np.uint)


tmp_key = cbc_w.ascii_to_arr(str(shared_key.x))

for i in range(min(tmp_key.size, key.size)):
    key[i] = tmp_key[i]


msg_arr = cbc_w.ascii_to_arr(msg)
num_blcks = int(np.ceil(msg_arr.size / 16.0))
msg_2d = np.full((num_blcks, 16), 0x20, dtype=np.uint)
    # print("num blocks: ", num_blcks)
for row in range(num_blcks):
    for col in range(16):
        if (row*16+col < msg_arr.size):
            msg_2d[row][col] = msg_arr[row*16+col]
        else:
            break
# print(msg_2d)
cbc_w.is_encrypting = False
plainText = cbc_w.crypt_loop(msg_2d, key)
print("key: \n", key)
print("Ciphertext: ", msg)

print("Deciphered: ", cbc_w.arr_to_ascii(np.reshape(plainText, -1)))


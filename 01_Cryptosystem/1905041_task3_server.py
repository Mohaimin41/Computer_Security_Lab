import importlib
import socket
import numpy as np

aes = importlib.import_module("1905041_aes")
cbc = importlib.import_module("1905041_cbc")
ecdh = importlib.import_module("1905041_ecdh")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Server socket successfully created")

port = 12345

s.bind(('', port))
print("server socket binded to %s" % (port))

s.listen(5)
print("server socket is listening")

while True:

    # Establish connection with client.
    c, addr = s.accept()
    print('Got connection from: ', addr)

    # send a thank you message to the client. encoding to send byte type.
    c.send("Connected Successfully".encode())
    incoming = c.recv(1024).decode()
    
    ecdh_worker = ecdh.ECDH_client(128)
    curve, gen_point = ecdh_worker.mk_curve_and_gen_point(128)
    priv_key, public_key = ecdh_worker.mk_keys(curve, gen_point)
    shared_key = None
    other_public_key = None

    if (incoming == "ack conn"):
        c.send(str(curve.Prime).encode())
    incoming = c.recv(1024).decode()
    if (incoming == "ack prime"):
        c.send(str(curve.a).encode())
    incoming = c.recv(1024).decode()
    if (incoming == "ack a"):
        c.send(str(curve.b).encode())
    incoming = c.recv(1024).decode()
    if (incoming == "ack b"):
        c.send(str(gen_point.x).encode())
    incoming = c.recv(1024).decode()
    if (incoming == "ack G.x"):
        c.send(str(gen_point.y).encode())
    incoming = c.recv(1024).decode()
    if (incoming == "ack G.y"):
        c.send(str(public_key.x).encode())
    incoming = c.recv(1024).decode()
    if (incoming == "ack Pub.x"):
        c.send(str(public_key.y).encode())
    incoming = c.recv(1024).decode()
    if (incoming == "ack Pub.y"):
        c.send("give key".encode())
    pub_x = int(c.recv(1024).decode())
    # print(pub_x)
    c.send("ack pubx".encode())
    pub_y = int(c.recv(1024).decode())
    other_public_key = ecdh.My_Point(pub_x, pub_y)
    
    shared_key = ecdh_worker.mk_shared_secret(other_public_key, priv_key)
    
    c.send(str(shared_key.x).encode())
    
    incoming = c.recv(1024).decode()

    if (incoming == str(shared_key.x)):
        print("ECDH done")
    
    cbc_w=cbc.CBC()
    msg = cbc_w.message_input()
    
    key = np.zeros(int(128/8), dtype=np.uint)


    tmp_key = cbc_w.ascii_to_arr(str(shared_key.x))

    for i in range(min(tmp_key.size, key.size)):
        key[i] = tmp_key[i]

    ciphertext = cbc_w.crypt_loop(msg, key)
    print("key: \n", key)
    print("\nCiphered Text:\nIn HEX: ", end="")
    temp = np.delete(ciphertext, 0,0)
    cbc_w.arr_print(np.reshape(temp, -1))
    t = cbc_w.arr_to_ascii(np.reshape(ciphertext, -1))
    print("In ASCII: ", cbc_w.arr_to_ascii(np.reshape(ciphertext, -1)))

    c.send(t.encode())
    
    print("Message sent, ending connection")
    c.close()
    break



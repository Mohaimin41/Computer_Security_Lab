import numpy as np
import secrets
import importlib

aes = importlib.import_module("1905041_aes")

# from aes import *

class CBC:
    def __init__(self) -> None:
        self.is_encrypting = True
        self.keygen_time = 0
        self.encryption_time = 0
        self.decryption_time = 0
        self.const_init_vector = np.array([210, 227, 218, 82, 139, 132,
                                 53, 252, 48, 60, 120, 208, 23, 171, 107, 142,])
        
        self.Initialization_Vector = self.const_init_vector

    def arr_print(self, arr: np.array) -> None:
        for i in range(arr.size):
            print("{0:X}".format(arr[i]), end=" ")
        print("")

    def arr_to_ascii(self, msg_array: np.array) -> str:
        msg = list()
        for i in range(msg_array.size):
            msg.append(chr(msg_array[i]))

        msg_str = "".join(msg)
        return msg_str

    def ascii_to_arr(self, msg: str) -> np.array:
        msg_list = list(msg)
        msg_arr = np.zeros(len(msg_list), dtype=np.uint)
        for i in range(len(msg_list)):
            msg_arr[i] = ord(msg_list[i])
        return msg_arr

    def message_input(self) -> np.array:
        msg = input("Enter message: ")
        msg_arr = self.ascii_to_arr(msg)
        num_blcks = int(np.ceil(msg_arr.size / 16.0))
        msg_2d = np.full((num_blcks, 16), 0x20, dtype=np.uint)
        # print("num blocks: ", num_blcks)
        for row in range(num_blcks):
            for col in range(16):
                if (row*16+col < msg_arr.size):
                    msg_2d[row][col] = msg_arr[row*16+col]
                else:
                    break
        return msg_2d

    def key_input(self) -> np.array:
        key = np.zeros(int(128/8), dtype=np.uint)

        for i in range(key.size):
            key[i] = secrets.randbits(8)

        str_key = input("Enter key: ")
        tmp_key = self.ascii_to_arr(str_key)

        for i in range(min(tmp_key.size, key.size)):
            key[i] = tmp_key[i]

        return key

    def crypt_loop(self, message: np.array, key: np.array) -> np.array:
        num_blcks = int(np.ceil(message.size / 16.0))
        crypted_arr = np.zeros(message.shape, dtype=np.uint)

        self.Initialization_Vector = np.zeros(16, dtype=np.uint)
        
        if self.is_encrypting:
            for i in range(self.Initialization_Vector.size):
                self.Initialization_Vector[i] = secrets.randbits(8)
            # print("encrypt IV:\n", self.Initialization_Vector)
            temp_IV = np.array([self.Initialization_Vector])
            
            
        else:
            self.Initialization_Vector = message[0]
            # print("decrypt IV: \n", self.Initialization_Vector)
            # print("decrypt message full:\n", message)
            message = np.delete(message, 0, 0)
            # print("decrypt msg cut:\n", message)
            num_blcks = num_blcks -1
            # print("decrypt message: ", message)

        for blck in range(num_blcks):
            if self.is_encrypting:
                crypted_arr[blck] = self.single_encrypt(message[blck], key)
            else:
                crypted_arr[blck] = self.single_decrypt(message[blck], key)
        
        if self.is_encrypting:
            crypted_arr = np.concatenate((temp_IV, crypted_arr), axis=0)
            # print("encrypt msg full: \n", crypted_arr)
        else:
            crypted_arr = crypted_arr[:-1]
        return crypted_arr

    def single_encrypt(self, msg_block: np.array, key: np.array) -> np.array:
        msg_block = msg_block ^ self.Initialization_Vector
        worker = aes.AES_block_crypto(key=key, message=msg_block)
        
        encrypted_blck = worker.encrypt_decrypt(is_encrypting=True)

        self.keygen_time = self.keygen_time + worker.keygen_time
        self.encryption_time = self.encryption_time + worker.crypt_time

        self.Initialization_Vector = encrypted_blck
        
        return encrypted_blck

    def single_decrypt(self, msg_block: np.array, key: np.array) -> np.array:
        worker = aes.AES_block_crypto(key=key, message=msg_block)
        decrypted_blck = worker.encrypt_decrypt(is_encrypting=False)

        self.keygen_time = self.keygen_time + worker.keygen_time
        self.decryption_time = self.decryption_time + worker.crypt_time

        decrypted_blck = decrypted_blck ^ self.Initialization_Vector

        self.Initialization_Vector = msg_block

        return decrypted_blck

    def output(self, key: np.array, input_msg: np.array, ciphertext: np.array, deciphered: np.array) -> None:
        print("Key:\nIn ASCII: ", self.arr_to_ascii(np.reshape(key, -1)))
        print("In HEX: ", end="")
        self.arr_print(key)

        print("\nPlain Text:\nIn ASCII: ",
              self.arr_to_ascii(np.reshape(input_msg, -1)))
        print("In HEX: ", end="")
        self.arr_print(np.reshape(input_msg, -1))

        print("\nCiphered Text:\nIn HEX: ", end="")
        temp = np.delete(ciphertext, 0,0)
        self.arr_print(np.reshape(temp, -1))
        print("In ASCII: ", self.arr_to_ascii(np.reshape(ciphertext, -1)))

        print("\nDeciphered Text:\nIn HEX: ", end="")
        self.arr_print(np.reshape(deciphered, -1))
        print("In ASCII: ", self.arr_to_ascii(np.reshape(deciphered, -1)))

        print("\nEncryption Time Details:\nKey Schedule Time: ", self.keygen_time, " ms")
        print("Encryption Time: ", self.encryption_time, " ms\nDecryption Time: ", self.decryption_time, " ms")

    def run(self) -> None:
        message = self.message_input()
        key = self.key_input()
        
        ciphertext = self.crypt_loop(message, key)

        self.is_encrypting = False
        deciphered = self.crypt_loop(ciphertext, key)

        self.output(key, input_msg=message, ciphertext=ciphertext, deciphered=deciphered)

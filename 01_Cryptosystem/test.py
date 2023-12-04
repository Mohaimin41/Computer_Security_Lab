# from aes import *

# aes = AES_block_crypto(np.array([0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
#  ]),
#        np.array([0x29,0xc3,0x50,0x5f,0x57,0x14,0x20,0xf6,0x40,0x22,0x99,0xb3,0x1a,0x2,0xd7,0x3a]))

# aes.gen_round_keys()
# print("key: ", np.vectorize(hex)(aes.key))
# print("message: ", np.vectorize(hex)(aes.message))
# print("byte key size: ", aes.keysize_bytes)
# print("num of rounds: ", aes.num_of_rounds)
# print("all round key size bytes: ", aes.round_keys.size)
# print("round const: ", np.vectorize(hex)(aes.round_consts), "\nround keys: \n")
# # for i in range(11):
# #     print(np.vectorize(hex)(aes.round_keys[i*16:i*16+16]))

# # aes.message = aes.message ^ aes.round_keys[:16]
# # print("aes message after round key 0 add: ",np.vectorize(hex)(aes.message))

# # temp_key = aes.get_round_key(1)
# # print("round 1 key: ", np.vectorize(hex)(temp_key))

# # aes.sub_byte(aes.message)
# # print("aes message subByte: ",np.vectorize(hex)(aes.message))

# # aes.message = aes.message.reshape((4, 4)).transpose()
# # aes.shift_rows()
# # print("aes message after shift row: ",np.vectorize(hex)(aes.message))

# # aes.mix_column()
# # print("aes message after mix column: ",np.vectorize(hex)(aes.message))

# # aes.message = aes.message.transpose().reshape(16)
# # aes.message = aes.message ^ temp_key
# # print("aes message after add roundkey: ",np.vectorize(hex)(aes.message))
# print("aes msg after encryption: ", np.vectorize(hex)( aes.encrypt_decrypt(False)))
from cbc import *
from aes import *

cry = CBC()

cry.run()
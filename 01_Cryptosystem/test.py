from aes import *

aes = AES_block_crypto(np.array([0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
                                 ]),
                       np.array([0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20, 0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F
                                 ]))

aes.gen_round_keys()
print("key: ", np.vectorize(hex)(aes.key))
print("message: ", np.vectorize(hex)(aes.message))
print("byte key size: ", aes.keysize_bytes)
print("num of rounds: ", aes.num_of_rounds)
print("all round key size bytes: ", aes.round_keys.size)
print("round const: ", np.vectorize(hex)(aes.round_consts), "\nround keys: \n")
for i in range(11):
    print(np.vectorize(hex)(aes.round_keys[i*16:i*16+16]))
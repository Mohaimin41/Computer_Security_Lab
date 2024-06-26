import numpy as np
import time
import BitVector as bv

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [bv.BitVector(hexstring="02"), bv.BitVector(hexstring="03"),
     bv.BitVector(hexstring="01"), bv.BitVector(hexstring="01")],
    [bv.BitVector(hexstring="01"), bv.BitVector(hexstring="02"),
     bv.BitVector(hexstring="03"), bv.BitVector(hexstring="01")],
    [bv.BitVector(hexstring="01"), bv.BitVector(hexstring="01"),
     bv.BitVector(hexstring="02"), bv.BitVector(hexstring="03")],
    [bv.BitVector(hexstring="03"), bv.BitVector(hexstring="01"),
     bv.BitVector(hexstring="01"), bv.BitVector(hexstring="02")]
]

InvMixer = [
    [bv.BitVector(hexstring="0E"), bv.BitVector(hexstring="0B"),
     bv.BitVector(hexstring="0D"), bv.BitVector(hexstring="09")],
    [bv.BitVector(hexstring="09"), bv.BitVector(hexstring="0E"),
     bv.BitVector(hexstring="0B"), bv.BitVector(hexstring="0D")],
    [bv.BitVector(hexstring="0D"), bv.BitVector(hexstring="09"),
     bv.BitVector(hexstring="0E"), bv.BitVector(hexstring="0B")],
    [bv.BitVector(hexstring="0B"), bv.BitVector(hexstring="0D"),
     bv.BitVector(hexstring="09"), bv.BitVector(hexstring="0E")]
]


class AES_block_crypto:
    def __init__(self, key: np.array, message: np.array) -> None:
        self.key = key
        self.message = message
        self.keysize_bytes = key.size
        self.num_of_rounds = 0
        if (self.keysize_bytes == 16):
            self.num_of_rounds = 10
        elif (self.keysize_bytes == 24):
            self.num_of_rounds = 12
        elif (self.keysize_bytes == 32):
            self.num_of_rounds = 14
        self.keygen_time = 0
        self.crypt_time = 0
        self.is_encrypting = True
        self.round_keys = np.zeros(
            (self.num_of_rounds + 1)*self.keysize_bytes, dtype=np.uint)
        self.round_consts = np.array(
            [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36], dtype=np.uint)
        self.sbox = np.array(Sbox, dtype=np.uint)
        self.inv_sbox = np.array(InvSbox, dtype=np.uint)

    def get_rcon_i(self, round_num: int) -> np.array:
        return np.array([self.round_consts[round_num - 1], 0x0, 0x0, 0x0], dtype=np.uint)

    def sub_byte(self, word: np.array) -> None:
        if self.is_encrypting:
            for i in range(word.size):
                word[i] = self.sbox[word[i]]
        else:
            for i in range(word.size):
                word[i] = self.inv_sbox[word[i]]

    # type: 1 = normal full operation, 2 = special only substitution, 3 = only xor
    def round_const_op(self, word_idx: int, round_num: int, type: int) -> np.array:
        rcon_i = np.zeros(4, dtype=np.uint)
        word_i_1 = np.array(
            self.round_keys[(word_idx - 1) * 4:(word_idx - 1) * 4 + 4], dtype=np.uint)
        if (type == 1):
            word_i_1 = np.roll(word_i_1, -1)
            self.sub_byte(word_i_1)
            rcon_i = self.get_rcon_i(round_num)
        elif (type == 2):
            self.sub_byte(word_i_1)

        N = int(self.keysize_bytes/4)

        word_i_N = np.array(
            self.round_keys[(word_idx - N) * 4:(word_idx - N) * 4 + 4], dtype=np.uint)

        word_i_1 = (word_i_1 ^ word_i_N)
        if (type == 1):
            word_i_1 = word_i_1 ^ rcon_i

        return word_i_1

    def gen_round_keys(self) -> None:
        N = int(self.keysize_bytes/4)  # word size
        start_time = time.time_ns() 
        for i in range(4 * (self.num_of_rounds + 1)):
            word_i = np.zeros(4, dtype=np.uint)
            if (i < N):
                word_i = np.array(self.key)[i*4:i*4+4]

            elif (i >= N and i % N == 0):
                word_i = self.round_const_op(i, int(i/4), 1)

            elif (i >= N and N > 6 and i % N == 4):
                word_i = self.round_const_op(i, int(i/4), 2)
            else:
                word_i = self.round_const_op(i, int(i/4), 3)

            self.round_keys[i*4: i*4 + 4] = word_i
        self.keygen_time = (time.time_ns() - start_time)/ (10 ** 6)

    def get_round_key(self, num_round: int) -> np.array:
        temp_key = np.zeros(16)
        if self.is_encrypting:
            temp_key = self.round_keys[num_round*16:num_round*16+4*4]
        else:
            temp_key = self.round_keys[(
                self.num_of_rounds - num_round)*16: (self.num_of_rounds - num_round)*16 + 4*4]
        return temp_key

    def shift_rows(self) -> None:
        shift_amount = 0
        if self.is_encrypting:
            shift_amount = -1
        else:
            shift_amount = 1
        for i in range(4):
            self.message[i] = np.roll(self.message[i], shift_amount*i)

    def mix_column(self) -> None:
        AES_modulus = bv.BitVector(bitstring='100011011')
        
        temp_msg = np.zeros((4,4), dtype=np.uint)
        
        for row in range(4):
            for col in range(4):
                tmp_sum = 0
                for c in range (4):
                    if self.is_encrypting:
                        tmp_val = Mixer[row][c].gf_multiply_modular(bv.BitVector(intVal=self.message[c][col]), AES_modulus, 8)
                    else:
                        tmp_val = InvMixer[row][c].gf_multiply_modular(bv.BitVector(intVal=self.message[c][col]), AES_modulus, 8)
                    tmp_sum = tmp_sum ^ tmp_val.int_val()
                temp_msg[row][col] = tmp_sum

        self.message = temp_msg
        pass

    def single_encrypt_round(self, num_round: int) -> None:
        temp_key = self.get_round_key(num_round+1)

        self.sub_byte(self.message)

        self.message = self.message.reshape((4, 4)).transpose()
        self.shift_rows()

        self.mix_column()

        self.message = self.message.transpose().reshape(16)
        self.message = self.message ^ temp_key

    def single_decrypt_round(self, num_round: int):
        temp_key = self.get_round_key(num_round+1)

        self.message = self.message.reshape((4, 4)).transpose()
        self.shift_rows()
        self.message = self.message.transpose().reshape(16)

        self.sub_byte(self.message)

        self.message = self.message ^ temp_key

        self.message = self.message.reshape((4, 4)).transpose()
        self.mix_column()
        self.message = self.message.transpose().reshape(16)

    def main_loop(self) -> None:
        start_time = time.time_ns()

        for num_round in range(self.num_of_rounds):
            if self.is_encrypting:
                if (num_round == 9):
                    temp_key = self.get_round_key(num_round + 1)
                    self.sub_byte(self.message)
                    
                    self.message = self.message.reshape((4, 4)).transpose()
                    self.shift_rows()
                    
                    self.message = self.message.transpose().reshape(16)
                    self.message = self.message ^ temp_key
                else:
                    self.single_encrypt_round(num_round)
            else:
                if (num_round == 9):
                    temp_key = self.get_round_key(num_round + 1)
                    
                    self.message = self.message.reshape((4, 4)).transpose()
                    self.shift_rows()
                    
                    self.message = self.message.transpose().reshape(16)
                    self.sub_byte(self.message)
                    
                    self.message = self.message ^ temp_key
                else:
                    self.single_decrypt_round(num_round)
        
        self.crypt_time = (time.time_ns() - start_time)/ (10 ** 6)

    def encrypt_decrypt(self, is_encrypting: bool) -> np.array:
        self.is_encrypting = is_encrypting
        temp_key = self.get_round_key(0)
        self.message = self.message ^ temp_key
        self.main_loop()
        return self.message

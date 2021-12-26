import argparse

from collections import deque
from itertools import repeat
from bitstring import BitArray
from Crypto.Cipher import AES

from utils.utils import validate_size,to_bytes
from db import db_handler
from constants import constants
from utils import utils

class AES128Test:
    @staticmethod
    def encrypt(key, iv, plaintext):
        """Metodo encargado de realizar el cifrado de un plaintext en modo de operacion CBC
        :Parametros:
            key : str hex
                llave
            iv : str hex
                vector de inicialización
            plaintext : bytes
                texto plano
        :Return: 
            cipher_text : bytes
        """
        return AES.new(bytes.fromhex(key), AES.MODE_CBC, bytes.fromhex(iv)).encrypt(validate_size(to_bytes(plaintext, 'latin 1'), 16)).hex()

class TriviumTest:

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.inicializacion()
        
    def inicializacion(self):
        key = to_bytes(self.key,constants.encoding_hex)
        iv = to_bytes(self.iv,constants.encoding_hex)

        key = BitArray(key)
        key.byteswap()
        key = list(map(int, key.bin))

        iv = BitArray(iv)
        iv.byteswap()
        iv = list(map(int, iv.bin))

        # Initialize state
        # (s1; s2; : : : ; s93) (K1; : : : ; K80; 0; : : : ; 0)
        init_state = key
        init_state += list(repeat(0, 13))

        # (s94; s95; : : : ; s177) (IV1; : : : ; IV80; 0; : : : ; 0)
        init_state += iv
        init_state += list(repeat(0, 4))

        # (s178; s279; : : : ; s288) (0; : : : ; 0; 1; 1; 1)
        init_state += list(repeat(0, 108))
        init_state += [1, 1, 1]

        self.state = deque(init_state)

        # Do 4 Full cycle clock
        for _ in range(4*288):
            self.gen_keystream()

    def gen_keystream(self):
        t_1 = self.state[65] ^ self.state[92]
        t_2 = self.state[161] ^ self.state[176]
        t_3 = self.state[242] ^ self.state[287]

        z = t_1 ^ t_2 ^ t_3

        t_1 = t_1 ^ self.state[90] & self.state[91] ^ self.state[170]
        t_2 = t_2 ^ self.state[174] & self.state[175] ^ self.state[263]
        t_3 = t_3 ^ self.state[285] & self.state[286] ^ self.state[68]

        self.state.rotate()

        self.state[0] = t_3
        self.state[93] = t_1
        self.state[177] = t_2

        return z

    def keystream(self, msglen):
        # Generete keystream
        counter = 0
        keystream = []

        while counter < msglen:
            keystream.append(self.gen_keystream())
            counter += 1

        return keystream

    def decrypt(self, plaintext):
        all_chiper = []

        msg = to_bytes(plaintext, 'latin 1')

        for i in range(len(msg)):
            hex_plain = hex(msg[i])

            if len(hex_plain) < 4:
                hex_plain = '0x0'+hex_plain[-1]

            keystream = self.keystream(8)
            keystream = '0b' + ''.join(str(i) for i in keystream[::-1])
            keystream = BitArray(keystream)
            keystream.byteswap()

            plain = BitArray(hex_plain)
            plain.byteswap()

            cipher = [x ^ y for x, y in zip(
                map(int, list(plain)), map(int, list(keystream)))]
            cipher = '0b' + ''.join(str(i) for i in cipher)
            cipher = BitArray(cipher)
            cipher.byteswap()

            all_chiper.append(int.from_bytes(cipher.tobytes(),'big'))

            print('{: ^15}{: ^15}{: ^15}{: ^15}{: ^15}{:^15}'.format(
                hex_plain, plain.bin, keystream.bin, keystream.hex, cipher.bin, '0x' + cipher.hex.upper()))

        return bytes(all_chiper).hex()
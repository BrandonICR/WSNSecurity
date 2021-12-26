import argparse

from collections import deque
from itertools import repeat
from bitstring import BitArray
from utils.utils import reverse_bytes, to_bytes
from db import db_handler
from constants import constants

#Edited By BrandonICR
#Credits Github user: uisyudha

class Trivium:

    state = None
    state_backup = None
        
    @staticmethod
    def inicializacion():
        Trivium.state = None
        
        key = to_bytes(db_handler.get_key(constants.str_trivium),constants.encoding_hex)
        iv = to_bytes(db_handler.get_iv(constants.str_trivium),constants.encoding_hex)

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

        Trivium.state = deque(init_state)

        # Do 4 Full cycle clock
        for _ in range(4*288):
            Trivium.gen_keystream()
        
        Trivium.state_backup = Trivium.state.copy()

    @staticmethod
    def gen_keystream():
        t_1 = Trivium.state[65] ^ Trivium.state[92]
        t_2 = Trivium.state[161] ^ Trivium.state[176]
        t_3 = Trivium.state[242] ^ Trivium.state[287]

        z = t_1 ^ t_2 ^ t_3

        t_1 = t_1 ^ Trivium.state[90] & Trivium.state[91] ^ Trivium.state[170]
        t_2 = t_2 ^ Trivium.state[174] & Trivium.state[175] ^ Trivium.state[263]
        t_3 = t_3 ^ Trivium.state[285] & Trivium.state[286] ^ Trivium.state[68]

        Trivium.state.rotate()

        Trivium.state[0] = t_3
        Trivium.state[93] = t_1
        Trivium.state[177] = t_2

        return z

    @staticmethod
    def keystream(msglen):
        # Generete keystream
        counter = 0
        keystream = []

        while counter < msglen:
            keystream.append(Trivium.gen_keystream())
            counter += 1

        return keystream

    @staticmethod
    def decrypt(msg):
        all_chiper = []

        for i in range(len(msg)):
            hex_plain = hex(msg[i])

            if len(hex_plain) < 4:
                hex_plain = '0x0'+hex_plain[-1]

            keystream = Trivium.keystream(8)
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

        Trivium.state = Trivium.state_backup.copy()

        return bytes(all_chiper)

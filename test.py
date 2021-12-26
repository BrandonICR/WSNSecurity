from resources import create_app
import db.db_handler as db_handler
from cryptography.trivium import Trivium
from cryptography.aes128 import AES128
from utils.utils import reverse_bytes, to_bytes, to_string,reverse_bytes
from constants import constants

app, login_manager = create_app()

def test_trivium():
    previous_key = to_bytes(db_handler.get_key(constants.str_trivium),constants.encoding_hex)
    previous_iv = to_bytes(db_handler.get_iv(constants.str_trivium),constants.encoding_hex)
    try:

        new_key = b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00'#b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
        new_iv = b'\x6e\x83\xee\x99\xae\x19\x2e\x85\x44\x59'
        plaintext = reverse_bytes(b'\x51\x52\x53\x00\x00\x00\x00\x00\x00\x00')

        db_handler.set_key(to_string(new_key, constants.encoding_hex), constants.str_trivium)
        db_handler.set_iv(to_string(new_iv, constants.encoding_hex), constants.str_trivium)

        Trivium.inicializacion()
        ciphertext = Trivium.decrypt(plaintext)
        ciphertext2 = Trivium.decrypt(ciphertext)

        print('key:',new_key.hex())
        print('iv:',new_iv.hex())
        print('plaintext:',plaintext.hex())
        print('ciphertext:',ciphertext.hex())
        print('ciphertext2:',ciphertext2.hex())

    finally:
        db_handler.set_key(to_string(previous_key, constants.encoding_hex), constants.str_trivium)
        db_handler.set_iv(to_string(previous_iv, constants.encoding_hex), constants.str_trivium)


if __name__ == '__main__':
    db_handler.create_all()
    Trivium.inicializacion()
    AES128.set_default_key_iv()
    test_trivium()
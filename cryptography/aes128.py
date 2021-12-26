from Crypto.Cipher import AES

from utils.utils import validate_size
from db import db_handler
from constants import constants
from utils import utils

class AES128:

    cipher = None

    @staticmethod
    def set_default_key_iv():
        AES128.class_key = utils.to_bytes(db_handler.get_key(constants.str_aes), constants.encoding_hex)
        AES128.class_iv = utils.to_bytes(db_handler.get_iv(constants.str_aes), constants.encoding_hex)
        AES128.cipher = AES.new(AES128.class_key, AES.MODE_CBC, AES128.class_iv)

    @staticmethod
    def set_key():
        AES128.class_key = utils.to_bytes(db_handler.get_key(constants.str_aes), constants.encoding_hex)
        AES128.refresh_cipher()
    
    @staticmethod
    def set_iv():
        AES128.class_iv = utils.to_bytes(db_handler.get_iv(constants.str_aes), constants.encoding_hex)
        AES128.refresh_cipher()
    
    @staticmethod
    def refresh_cipher():
        AES128.cipher = AES.new(AES128.class_key, AES.MODE_CBC, AES128.class_iv)

    @staticmethod
    def decrypt(cipher_text):
        """Metodo encargado de realizar el descifrado de un ciphertext en modo de operacion CBC
        :Parametros:
            cipher_text : bytes
                texto cifrado
        :Return: 
            plain_text : bytes
        """
        plain_text = AES128.cipher.decrypt(validate_size(cipher_text, 16))
        return plain_text

    
    @staticmethod
    def encrypt(plain_text):
        """Metodo encargado de realizar el cifrado de un plaintext en modo de operacion CBC
        :Parametros:
            plain_text : bytes
                texto plano
        :Return: 
            cipher_text : bytes
        """
        aes_encrypt = AES.new(AES128.class_key, AES.MODE_CBC, AES128.class_iv)
        return aes_encrypt.encrypt(plain_text)

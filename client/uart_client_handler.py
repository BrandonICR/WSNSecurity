import time
import constants.constants as constants
from db import db_handler

from client.uart_client import UartClient
from utils.utils import to_string, get_date, to_bytes, reverse_bytes, validate_cipher_key
from cryptography.aes128 import AES128
from cryptography.trivium import Trivium
from log.logger import log_info

def inicializar_lectura():
    """Metodo encargado de inicializar la lectura del puerto COM en servidor de uart
    :Parametros:
    :Return: 
    """
    s = UartClient()
    s.send_message(b'inicializar')
    msg = s.get_message()
    s.close_socket()
    return msg

def test_uart():
    """Metodo encargado de realizar un test al microcontrolador
    :Parametros:
    :Return: 
    """
    s = UartClient()
    s.send_message(b'test')
    status = s.get_message()
    iv = s.get_message()
    if status == b'AES' and iv != b'':
        db_handler.set_iv(to_string(iv, constants.encoding_hex), constants.str_aes)
        AES128.set_iv()
    elif status == b'TRIVIUM' and iv != b'':
        db_handler.set_iv(to_string(iv, constants.encoding_hex), constants.str_trivium)
        Trivium.inicializacion()
    s.close_socket()
    return status

def enviar_key(key, algorithm):
    """Metodo encargado de enviar la llave al microcontrolador
    """
    s = UartClient()
    s.send_message(b'key')
    print('KEEY:',key)
    cipher_key = AES128.encrypt(key) if algorithm == constants.str_aes else Trivium.decrypt(reverse_bytes(key))
    if not validate_cipher_key(cipher_key): return 'FAIL'
    print("Llave validada")
    s.send_message(cipher_key)
    s.send_message(to_bytes(algorithm, constants.encoding_latin1))
    status = s.get_message()
    if status == constants.bytes_ok_message and algorithm == constants.str_trivium:
        db_handler.set_key(to_string(key, constants.encoding_hex), constants.str_trivium)
        Trivium.inicializacion()
    elif status == constants.bytes_ok_message and algorithm == constants.str_aes:
        db_handler.set_key(to_string(key, constants.encoding_hex), constants.str_aes)
        AES128.set_key()
    s.close_socket()
    print(status)
    return to_string(status, constants.encoding_latin1)

def enviar_texto_cifrado(algorithm, plaintext, encoding):
    """Metodo encargado de manipular el UartClient para enviar el texto plano al servidor de controlador de uart
    :Parametros:
        algorithm: str
            Algoritmo seleccionado actual
        plaintext : bytes
            Recibe el texto cifrado a transmitir.
        encoding : str
            Recibe el tipo de encoding ejemplo ('latin 1','hex')
    :Return: 
        diccionario : 
            plaintext : bytes
            ciphertext : str
    """
    s = UartClient()

    # Indicamos que se trata de texto plano a enviar
    s.send_message(b'plaintext')
    
    # Indicamos el algoritmo del que se trata
    msg = to_bytes(algorithm, constants.encoding_latin1)
    s.send_message(msg)
    
    # Enviamos el texto a cifrar
    s.send_message(plaintext)
    
    # Convertimos de bytes a Cadena el texto plano
    msg = to_string(plaintext, encoding)
    print('Mensaje transmitido:',msg)

    # Enviamos la cantidad de bytes a transmitir
    encoding_bytes = bytes(encoding,constants.encoding_latin1)
    s.send_message(encoding_bytes)
    print('Encoding transmitido:',encoding)

    # Obtenemos el texto cifrado
    ciphertext = s.get_message()

    # Cerramos la conexion con el server
    s.close_socket()
    # Desciframos el texto cifrado
    if algorithm == 'TRIVIUM':
        plaintext = Trivium.decrypt(ciphertext)
    else:
        plaintext = AES128.decrypt(ciphertext)
    plaintext_hex = plaintext.hex()
    plaintext = to_string(plaintext, encoding)
    print("Texto descifrado:",plaintext)

    # Mostramos el texto cifrado recibido
    ciphertext = ciphertext.hex()
    print('Texto cifrado recibido:',ciphertext)

    # Almacenamos en el log el texto cifrado y descifrado
    instant = get_date()
    log_info(f"{instant}>{msg}>{ciphertext}>{plaintext_hex}")

    # Retornamos el texto plano y texto cifrado
    return {'plaintext':plaintext,'ciphertext':ciphertext,'date':instant,'error':'None'}

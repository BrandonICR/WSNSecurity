from datetime import datetime
from bitstring import BitArray
from constants import constants

def get_date():
    """Funcion que se encarga de validar el tamaño de una cadena de lo contrario le añade el padding especificador
    :Parametros:
        info : bytes
            bytes a verificar
        modulo : int
            multiplo deseado de cadena infor de bytes
    :Return: 
        info : bytes
            retorna la cadena info con padding si fue necesario
    """
    now = datetime.now()
    return str(now.day)+'/'+str(now.month)+'/'+str(now.year)+'-'+str(now.hour)+':'+str(now.minute)+':'+str(now.second)

def reverse_bytes(cadena_bytes):
    """Refleja cada byte de una cadena de bytes
    :Parametros:
        cadena_bytes: bytes
            cadena a reflejar
    :Return:
        cadena_invertida: bytes
            cadena reflejada
    """
    return bytes([int(BitArray(byte.to_bytes(1,'big')).bin[::-1],2) for byte in cadena_bytes])

def to_bytes(info, encoding):
    """Convierte una cadena tipo str a bytes con su encoding especificado
    :Parametros:
        info : str
            str a verificar
        encoding : str
            encoding ejemplo ('latin 1','hex')
    :Return: 
        info : str
            cadena con info de tipo str con encoding especificado
    """
    if encoding == constants.encoding_hex:
        info_encoding = bytes.fromhex(info)
    else:
        info_encoding = bytes(info, constants.encoding_latin1)
    return info_encoding


def to_string(info, encoding):
    """Convierte una cadena tipo bytes a str con su encoding especificado
    :Parametros:
        info : bytes
            bytes a verificar
        encoding : str
            encoding ejemplo ('latin 1','hex')
    :Return: 
        info : str
            cadena con info de tipo str con encoding especificado
    """
    if encoding == constants.encoding_hex:
        info_encoding = info.hex()
    else:
        info_encoding = info.decode(constants.encoding_latin1)
    return info_encoding

def validate_size(info, modulo):
    """Valida el tamaño de una cadena de lo contrario le añade el padding especificador
    :Parametros:
        info : bytes
            bytes a verificar
        modulo : int
            multiplo deseado de cadena infor de bytes
    :Return: 
        info : bytes
            retorna la cadena info con padding si fue necesario
    """
    if(len(info) % modulo != 0):
        return (b'\x00'*(modulo-len(info) % modulo))+info
    return info

def validate_cipher_key(cipher_key):
    """Valida que dentro de la llave cifrada no se encuentre el hexadecimal '14'
    :Parametros:
        cipher_key : bytes
            llave cifrada
    :Return: 
        boolean
            True si la llave no contiene '14'
    """
    index = 0
    key_hex = cipher_key.hex()
    while index != -1:
        index = key_hex.find("14", index)
        if index >= 0 and index%2 == 0:
            return False
        if index == -1: return True
        index+=1
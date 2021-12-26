import threading
import serial
import socket
import time

import properties as properties
from utils.utils import to_string, validate_size

HOST = properties.uart_host  # Host del Socket de TCP
PORT = properties.uart_port  # Puerto del Socket de TCP

# Inicializar el Serial del puerto COM
ser = serial.Serial(properties.uart_com,baudrate=properties.uart_baudrate,timeout=1)

# Variables globales
encoding = ''
algorithm = 'AES'

# Funcion que se encarga de escribir el texto plano en el serial
def send_plaintext(algorithm,info,modulo):
    """Metodo encargado de escribir el texto plano en el COM
    :Parametros:
        algorithm: bytes
            algoritmo de cifrado seleccionado
        info : bytes
            informacion a transmiti
        modulo : int
            modulo al que debe ser multiplo el mensaje, si no añade padding
    :Return:
    """
    # Obtenemos la cadena con el encoding recivido
    msg = to_string(info, encoding)
    # Verificamos que la cadena a transmitir sea multiplo de 16 de lo contrario le hacemos padding
    msg_normalize = info
    len_text = len(info)
    if algorithm != b'TRIVIUM':
        msg_normalize = validate_size(info,modulo)
        len_text = len(msg_normalize)
    # Enviamos el caracter indicando que se trata de un mensaje
    ser.write(properties.metadata_init_msg)
    # Escribimos la cadena en el serial del puerto COM
    write_int = ser.write(msg_normalize)
    # Enviamos el caracter de termino de mensaje a cifrar
    ser.write(properties.metadata_end_msg)
    # Mostramos los datos recibidos
    print("Mensaje (como cadena) transmitido:",msg,' tamaño:',len_text,' escrito:',write_int)
    return len_text

def send_key(key, algorithm):
    """Metodo encargado de transmitir por el puerto COM la llave
    :Parametros:
        key: bytes
            Llave a transmitir
    :Return:
        status: bytes
            Estatus de respuesta
    """
    #Enviamos el metadato indicando que es una llave
    ser.write(properties.metadata_init_key)
    #Enviamos la llave
    print('LLAVE CIFRADA SERVIDOR: ',key)
    write_int = ser.write(key)
    #Enviamos el terminador de cadena
    ser.write(properties.metadata_end_msg)
    #Se espera respuesta del micro (metadato 0x16)
    msg = ser.read(1)
    status = b''
    print("Mensaje de estado:",msg)
    if msg == properties.metadata_response_success_key:
        print('Llave modificada con éxito') #Mostrar en interfaz
        status = b'OK'
    else:
        print('Error al modificar la llave') #Mostrar en interfaz
        status = b'FAIL'
    #Mostramos los datos
    print("Llave transmitida:",key," escrito:",write_int)
    return status

def test_uart(n):
    """Funcion encargada de realizar un test al microcontrolador, realizando n intentos.
    :Parametros:
        n : int Numero de intentos de comunicación con el microcontrolador.
    :Return:
        respose : 'FAIL' si no se logro comunicar con el micrcontrolador
                  'OK:ALG' si se logró comunicar con el microcontrolador
    """
    ser.write(properties.metadata_test)
    for _ in range(n):
        msg = ser.read(2)
        if msg == b'A0':
            iv = b''
            metadato = ser.read(1)
            if metadato == properties.metadata_init_iv:
                iv = ser.read(16)
            print("Metadato:",metadato)
            print("IV:",iv)
            return b'AES', iv
        elif msg == b'T0':
            iv = b''
            metadato = ser.read(1)
            if metadato == properties.metadata_init_iv:
                iv = ser.read(10)
            print("Metadato:",metadato)
            print("IV:",iv)
            return b'TRIVIUM', iv
        elif msg == b'A1':
            print("Algoritmo AES, previamente recibido iv")
            return b'AES', b''
        elif msg == b'T1':
            print("Algoritmo Trivium, previamente recibido iv")
            return b'TRIVIUM', b''
        ser.write(properties.metadata_test)
    print("No se recibio respuesta del dispositivo")
    return b'FAIL', b''
    

def recive_data(conn):
    """Metodo encargado de recibir un mensaje al socket cliente
    :Parametros:
        conn : socket
            socket actual
    :Return:
        array : bytes
    """
    length = int.from_bytes(conn.recv(4), "big")
    return conn.recv(length)

def send_data(conn,msg):
    """Metodo encargado de enviar un mensaje al socket cliente
    :Parametros:
        conn : socket
            socket actual
        msg : bytes
            mensaje a transmitir
    :Return: 
    """
    conn.sendall(len(msg).to_bytes(4,'big'))
    conn.sendall(msg)

def main():
    global encoding
    # Instanciamos el socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Anclamos el socket a la ip y puerto
        s.bind((HOST, PORT))
        # Escuchamos a los clientes infinitamente
        s.listen()
        while True:
            # Aceptamos un cliente
            conn, addr = s.accept()
            print('Conectado con:', addr)
            data = recive_data(conn)
            print('Cadena recibida:',data)
            # Si es la primera vez que se cacha un cliente se iniciliza el thread de lectura
            #   del puerto COM
            if data == b'inicializar':
                send_data(conn,b'FAIL')
            elif data == b'test':
                status, iv = test_uart(3)
                send_data(conn,status)
                send_data(conn,iv)
            elif data == b'key':
                # Se recibe la llave a enviar
                key = recive_data(conn)
                print("Llave recibida:",key)
                algorithm = recive_data(conn)
                print("Algoritmo recibido:",algorithm)
                status = send_key(key, algorithm)
                send_data(conn, status)
            elif data == b'plaintext':
                # Se recibe el algoritmo a tratar
                algorithm = recive_data(conn)
                # Se recibe el texto plano
                plaintext = recive_data(conn)
                print("Encoding recibido:",plaintext)
                # Se recibe la codificacion usada
                encoding = recive_data(conn)
                print("Encoding recibido:",encoding)
                # Se realiza el envío del texto cifrado
                len_plaintext = send_plaintext(algorithm, plaintext, 16)
                # Se recibe el metadato
                metadato = b''
                if algorithm == b'TRIVIUM':
                    metadato = ser.read(1)
                # Se recibe el texto cifrado del microcontrolador
                ciphertext = b''
                if (metadato == properties.metadata_init_msg and algorithm == b'TRIVIUM') or algorithm == b'AES':
                    ciphertext = ser.read(len_plaintext)
                # Se envia al cliente el texto cifrado
                send_data(conn,ciphertext)
                print('Enviado ciphertext:',ciphertext)
            print('Conexion cerrada con:',addr)
            conn.close()
    finally:
        s.close()

if __name__ == '__main__':
    main()

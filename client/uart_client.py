import socket

from properties import uart_host, uart_port

HOST = uart_host  # Host del Socket de TCP
PORT = uart_port  # Puerto del Socket de TCP

class UartClient:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((HOST, PORT))

    def get_message(self):
        length = int.from_bytes(self.s.recv(4), "big")
        return self.s.recv(length)

    def send_message(self,msg):
        self.s.sendall(len(msg).to_bytes(4,'big'))
        self.s.sendall(msg)

    def close_socket(self):
        self.s.close()
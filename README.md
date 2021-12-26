WSN Security

This project was developed using python 3 and Flask, it is an MVC system where the AES 128 CBC and Trivium algorithms can be tested through a communication between the computer and a device such as a microcontroller that provides these algorithms.

The flow is as follow:
    1. The microcontroller and the computer agree on a same key.
    2. The microcontroller send the IV vector to the computer.
    3. The computer saved the IV vector in SQLite database.
    4. You can send encrypted messages from the computer to the microcontroller.
        4.1. The computer encrypts the message using the current key and iv vector. 
        4.2. The computer sends the message to the microcontroller with some control bytes.
        4.3. The microcontroller receives the message and then decrypt the message.
        4.4. The microcontroller responses with some data to the computer following de same flow.
    5. You can change the key, for this, the steps are as follow:
        5.1. The computer encrypts the new key with de current key.
        5.2. The computer sends the new key to the microcontroller.
        5.3. The microcontroller decrypts the new key and replace the old key.}
        5.4. The microcontroller responses to the computer with a status byte.
    6. Only for validation purposes, the system saves the results of encrypting and decrypting each message in a log, this log can be seen in the navigation tab.
    7. You can test the local algorithms in the prueba tab.

Architecture:
    Front end: 
        We use this module to interact with the system, this module uses Jinja2 integrating with Flask.
        This module has 4 tabs: index, home, profile, test, registry

    Uart Controller Server:
        This module creates a TCP server using the socket module provided by python3.
        This server performs the following tasks:
            1. Receive requests to use the current device that is connected by a COM port.
            2. Manage COM port using the Serial module provided by python3.
            3. Add the necessary metadata for effective communication with the microcontroller.
            4. Manage the transactions to send a key, a message and test.

    Flask server:
        This server contains the following modules:
            1. Controller: Manage the request that a client sends us and the current state.
            2. Client: This module is in charge of communication with the uart controller server, this creates and TCP Client using sockets.
            3. Cryptography: This module manages the algorithms of encyption like AES and Trivium, this module is communicated with db module.
            4. db: This module manage the SQLite database.
            5. Log: This module create a file to write and read logs.

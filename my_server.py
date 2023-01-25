import re
import socket
from hashlib import md5
from threading import Thread

# global variables
HOST = '127.0.0.1'
PORT = 50000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clients = set()
user_client = {}
active_usernames = []


# after getting a port, keeps listening on it and for each client connecting, a thread is made
def main():
    s.bind((HOST, PORT))
    s.listen(8)
    print(f'Serer running on port {PORT}')

    while True:
        try:
            client, address = s.accept()
            print(f'{address} was connected.')
            Thread(target=server_handler, args=(client,)).start()
        except Exception:
            break


# for each client this function keeps running on a thread so we will get the messages they send
def server_handler(client_socket: socket.socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            print(message)
            msg_handler(message, client_socket)
        except OSError:
            break


# this function gets one message and sends it for parsing. after parse gives data to command_handler.
def msg_handler(msg, client_socket):
    msg_split = msg_parse(msg)
    command = msg_split[0]
    key_value_arr = []
    for i in range(1, len(msg_split)):
        key_value_arr.append(option_parse(msg_split[i]))
    command_handler(command, key_value_arr, client_socket)


# this function parses a message into command and options
def msg_parse(msg):
    msg_split = msg.split(' -Option ')
    return msg_split


# this function parses options into key-values
def option_parse(option):
    option = option[1:-1]
    key, value = option.split(':')
    return key, value


# this function handles commands. depending on what command was sent by the client, it will call the appropriate function
def command_handler(cmd, arr, client_socket):
    if cmd == 'Make':
        sign_up(client_socket, arr)
    if cmd == 'Connect':
        log_in(client_socket, arr)
    if cmd == 'Group':
        welcome(client_socket, arr)
    if cmd == 'GM':
        group_send(arr, client_socket)
    if cmd == 'PM':
        private_send(arr)
    if cmd == 'Users':
        send_users(client_socket, arr)  # change? delete dic?
    if cmd == 'End':
        leave_notification(client_socket, arr)


# sends private messages without printing and reading them
def private_send(arr):
    msg_body = arr[3][1]
    from_user = arr[0][1]
    to_user = arr[2][1]
    key = arr[4][1]
    protocol = f'PM -Option <from:{from_user}> -Option <to:{to_user}> -Option <message_len:{len(msg_body)}>' \
               f' -Option <message_body:{msg_body}> -Option <key:{key}>'
    client = user_client.get(to_user)
    try:
        client.send(protocol.encode())
    except BrokenPipeError:
        print(f'Broken pipe error occurred when sending message to {to_user}')


# sends group messages
def group_send(arr, client_socket):
    msg_body = arr[2][1]
    user = arr[0][1]
    print(f'{user}: {msg_body}')
    protocol = f'GM -Option <from:{user}> -Option <message_len:{len(msg_body)}> -Option <message_body:{msg_body}>'
    chat_file = open('history.txt', 'at')
    chat_file.write(f'{user}: {msg_body}\n')
    chat_file.close()
    for client in clients:
        if client != client_socket:
            client.send(protocol.encode())


# check for username and password to be new and at least 6 chars
# if data are valid, username along with hashed password are stored in data.txt
def sign_up(client_socket, arr):
    username = arr[0][1]
    password = arr[1][1]

    nak_reason = ''
    accept = validate_username(username)
    if not accept:
        nak_reason = 'Username is not available.'
    if accept:
        if len(username) < 6 or len(password) < 6:
            accept = False
            nak_reason = 'Length of username and password\nmust be at least 6 characters.'

    if accept:
        hash_pass = md5(password.encode()).hexdigest()
        data_file = open('data.txt', 'at')
        data_file.write(f'{username} -> {hash_pass}\n')
        data_file.close()
        active_usernames.append(username)
        protocol = f'UserAccepted -Option <username:{username}>'
    else:
        protocol = f'UserNotAccepted -Option <reason:{nak_reason}>'
    client_socket.send(protocol.encode())


# check if username chosen is repetitive, returns false so it can't be chosen for sign up
def validate_username(username):
    try:
        data_file = open('data.txt')
        for line in data_file:
            user_pass = line.split(' -> ')
            if user_pass[0] == username:
                data_file.close()
                return False
        data_file.close()
        return True
    except FileNotFoundError:
        return True


# if username doesn't exist in data file -> user does not exist.
# if username exists but password doesn't match -> password incorrect.
# if username and password correct but a client already is using them -> This account is already logged in.
def log_in(client_socket, arr):
    username = arr[0][1]
    password = arr[1][1]

    user_exist, pass_match = validate_log(username, password)
    if not user_exist:
        nak_reason = 'User does not exist.'
        protocol = f'ERROR -Option <reason:{nak_reason}>'
    elif not pass_match:
        nak_reason = 'Password incorrect.'
        protocol = f'ERROR -Option <reason:{nak_reason}>'
    elif repetitive_log(username):
        nak_reason = 'This account is already logged in.'
        protocol = f'ERROR -Option <reason:{nak_reason}>'
    else:
        active_usernames.append(username)
        protocol = f'Connected -Option <username:{username}>'
    client_socket.send(protocol.encode())


# checks if username exists among accounts and if it is, checks if the password is correct. returns result to log_in()
def validate_log(username, password):
    pass_hash = md5(password.encode()).hexdigest()
    user_exist = False
    pass_match = False
    try:
        data_file = open('data.txt')
        for line in data_file:
            user_pass = re.split(' -> |\n', line)
            if user_pass[0] == username:
                user_exist = True
                if user_pass[1] == pass_hash:
                    pass_match = True
                data_file.close()
                break
        data_file.close()
    except FileNotFoundError:
        pass
    return user_exist, pass_match


# returns true if account is already logged in
def repetitive_log(username):
    try:
        active_usernames.index(username)
        return True
    except ValueError:
        return False


# adds new member to active_users and send welcome and join notification
def welcome(client_socket, arr):
    clients.add(client_socket)
    username = arr[0][1]
    user_client.update({username: client_socket})
    print(f'{username} joined to the server.')
    for client in clients:
        if client == client_socket:
            protocol = f'Hello -Option <username:{username}>'
        else:
            protocol = f'Welcome -Option <username:{username}>'
        client.send(protocol.encode())


# sends active usernames to clients that request for it
def send_users(client_socket, arr):
    client_username = arr[0][1]
    protocol = 'USERS_LIST:\r\n'
    first = True
    for username in active_usernames:
        if not username == client_username:
            if first:
                first = False
            else:
                protocol += '|'
            protocol += f'<{username}>'
    client_socket.send(protocol.encode())


# when a user leaves, sends leave notification, closes its socket and removes it from clients and active_usernames array
def leave_notification(client_socket, arr):
    user = arr[0][1]
    active_usernames.remove(user)
    print(f'{user} left the server.')
    protocol = f'Leave -Option <username:{user}>'
    client_socket.close()
    clients.remove(client_socket)
    for client in clients:
        client.send(protocol.encode())


if __name__ == '__main__':
    print("Run main.py")

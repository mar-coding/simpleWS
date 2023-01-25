import socket
from base64 import urlsafe_b64encode
from hashlib import md5
from random import randint
from threading import Thread
import tkinter as tk
from tkinter import scrolledtext as st
from cryptography.fernet import Fernet

# global variables
HOST = '127.0.0.1'
PORT = 50000
USERNAME = ''
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
active_users = ['everyone']
msg_reg = 'Enter data...'
msg_win = ''


# connects to server then runs sign-up gui. after that runs chat screen gui.
def main():
    s.connect((HOST, PORT))
    auth_gui()
    msg_gui()


# opens for user to authenticate. if succeeded will close.
def auth_gui():
    # depending on drop menu calls the right function
    def register():
        nonlocal usr_input
        nonlocal pass_input
        status = var.get()
        usr = usr_input.get()
        pss = pass_input.get()
        if status == 'sign':
            sign_up(usr, pss)
        if status == 'log':
            log_in(usr, pss)

    # prints the message that came from the server if the sign/log was not accepted.
    # if info is 'done' it means that the sign/log has been successful
    def info_update():
        info = globals()['msg_reg']
        if info == 'done':
            window.destroy()
        else:
            nonlocal info_lbl
            info_lbl['text'] = f'{info}'

    # if user clicks close button
    def stop():
        window.destroy()
        s.close()
        exit(0)

    window = tk.Tk()
    window.geometry("300x255")
    window.title("Sign up/Log in tab")

    info_lbl = tk.Label(window, text=f'{msg_reg}')
    info_lbl.grid(column=0, row=0, pady=(20, 0), columnspan=2)

    var = tk.StringVar(window, 'log')
    tk.Radiobutton(window, text='Sign up', variable=var, value='sign').grid(column=0, row=1, pady=(15, 3), padx=7)
    tk.Radiobutton(window, text='Log in', variable=var, value='log').grid(column=0, row=2, pady=(0, 15))

    usr_lbl = tk.Label(window, text="Username")
    usr_lbl.grid(column=0, row=3)
    usr_input = tk.Entry(window, width=20)
    usr_input.grid(column=1, row=3)
    pass_lbl = tk.Label(window, text="Password")
    pass_lbl.grid(column=0, row=4)
    pass_input = tk.Entry(window, width=20)
    pass_input.grid(column=1, row=4)

    reg_btn = tk.Button(window, text='Go', height=1, width=10, command=lambda: [register(), info_update()])
    reg_btn.grid(column=0, row=5, pady=(15, 0), columnspan=2)

    window.protocol("WM_DELETE_WINDOW", stop)
    window.mainloop()


# is called if the user had chosen sign up in auth_gui
def sign_up(username, password):
    globals()['USERNAME'] = username
    protocol = f'Make -Option <user:{username}> -Option <pass:{password}>'
    s.send(protocol.encode())
    receive_msg()


# is called if the user had chosen log in in auth_gui
def log_in(username, password):
    globals()['USERNAME'] = username
    protocol = f'Connect -Option <user:{username}> -Option <pass:{password}>'
    s.send(protocol.encode())
    receive_msg()


# this function is called on a thread and listens for messages that are sent by the server
def listen_msg():
    while True:
        try:
            receive_msg()
        except Exception:
            pass


# this function gets one message and sends it for parsing. after parse gives data to command_handler.
def receive_msg():
    msg = s.recv(1024)
    if msg:
        msg_split = msg_parse(msg.decode())
        command = msg_split[0]
        key_value_arr = []
        for i in range(1, len(msg_split)):
            key_value_arr.append(option_parse(msg_split[i]))
        command_handler(command, key_value_arr)


# this function parses a message into command and options. same as in server.
def msg_parse(msg):
    msg_split = msg.split(' -Option ')
    return msg_split


# this function parses options into key-values. same as in server.
def option_parse(option):
    option = option[1:-1]
    key, value = option.split(':')
    return key, value


# this function handles commands. depending on what command was sent by the server, it will call the appropriate function
def command_handler(cmd, arr):
    if cmd == 'UserNotAccepted' or cmd == 'ERROR':
        reason = arr[0][1]
        globals()['msg_reg'] = reason
    if cmd == 'UserAccepted' or cmd == 'Connected':
        globals()['msg_reg'] = f'done'
        username = arr[0][1]
        introduce(username)
    if cmd == 'GM':
        gm_print(arr)
    if cmd == 'PM':
        pm_print(arr)
    if cmd.startswith('USERS_LIST'):
        give_users(cmd)
    if cmd == 'Hello':
        username = arr[0][1]
        chat_print(f'Hi {username}! welcome to the chat room.')
    if cmd == 'Welcome':
        username = arr[0][1]
        chat_print(f'{username} joined the chat room!')
    if cmd == 'Leave':
        username = arr[0][1]
        chat_print(f'{username} left the chat room.')


# sends 'group' protocol to server
def introduce(username):
    protocol = f'Group -Option <user:{username}>'
    s.send(protocol.encode())


# prints a group message in chat box
def gm_print(arr):
    msg_sender = arr[0][1]
    msg_body = arr[2][1]
    globals()['msg_win'].config(state='normal')
    globals()['msg_win'].insert('end', f'{msg_sender}: {msg_body}' + '\n')
    globals()['msg_win'].yview('end')
    globals()['msg_win'].config(state='disabled')


# prints a private message in chat box
def pm_print(arr):
    msg_sender = arr[0][1]
    msg_body = arr[3][1]
    key = arr[4][1]
    hashed_key = Fernet(urlsafe_b64encode(md5(key.encode()).hexdigest().encode()))
    msg = hashed_key.decrypt(msg_body.encode()).decode()
    globals()['msg_win'].config(state='normal')
    globals()['msg_win'].insert('end', f'{msg_sender} to you: {msg}' + '\n')
    globals()['msg_win'].yview('end')
    globals()['msg_win'].config(state='disabled')


# gets the users sent by the server and parses the message and updates active_users global array
def give_users(cmd):
    users = cmd.split('\r\n')[1].split('|')
    globals()['active_users'].clear()
    globals()['active_users'].append('everyone')
    for i in range(len(users)):
        if len(users[i]) > 0:
            globals()['active_users'].append(users[i][1:-1])


# is called when a message like leaving or joining wants to be printed on chat box
def chat_print(string):
    globals()['msg_win'].config(state='normal')
    globals()['msg_win'].insert('end', f'{string}' + '\n')
    globals()['msg_win'].yview('end')
    globals()['msg_win'].config(state='disabled')


# after authentication is done, user inters chatting area in this gui
def msg_gui():
    # when a drop box option is selected, this function is called to update the reciever
    def change_receiver(val):
        nonlocal receiver
        receiver = val
        nonlocal receiver_label
        receiver_label['text'] = f'to: {receiver}'

    # when new users are gotten from the server, this function is called to update dropbox options
    def update_drop():
        nonlocal drop
        menu = drop.children['menu']
        menu.delete(0, 'end')
        active = globals()['active_users']
        for username in active:
            menu.add_command(label=username,
                             command=lambda user=username: [variable.set(user), change_receiver(variable.get())])

    # this function is called when the window is closed. navigating to leave function
    def stop():
        window.destroy()
        leave()

    # default value
    receiver = 'everyone'

    window = tk.Tk()
    window.title(f'{USERNAME}\'s chat screen')

    chat_label = tk.Label(window, text="Messages:")
    chat_label.pack(padx=0, pady=(15, 3))

    globals()['msg_win'] = st.ScrolledText(window, width=50)
    globals()['msg_win'].config(state='disabled')
    globals()['msg_win'].pack(padx=15, pady=0)

    chat_label = tk.Label(window, text="Type your message...")
    chat_label.pack(padx=30, pady=(15, 3))

    input_area = tk.Entry(window, width=20)
    input_area.pack(ipadx=0, pady=(0, 10))

    users_btn = tk.Button(window, text='Get usernames', height=1, width=10,
                          command=lambda: [get_users(), update_drop()])
    users_btn.pack(padx=0, pady=(5, 5))

    # set gives the default value
    variable = tk.StringVar(window)
    variable.set(active_users[0])
    drop = tk.OptionMenu(window, variable, *active_users, command=change_receiver)
    drop.pack()

    receiver_label = tk.Label(window, text=f"to: {receiver}")
    receiver_label.pack(padx=30, pady=(3, 10))

    send_btn = tk.Button(window, text='Send', height=1, width=10, command=lambda: send_msg(input_area, receiver))
    send_btn.pack(padx=0, pady=(0, 5))

    exit_btn = tk.Button(window, text='Leave', height=1, width=10, command=stop)
    exit_btn.pack(padx=0, pady=(0, 15))

    window.protocol("WM_DELETE_WINDOW", stop)

    # we start the listening thread here so it has access to the global variables that we set here
    Thread(target=listen_msg, daemon=True).start()
    window.mainloop()


# whether a gm or a pm is wanted to be sent throw the gui, this function is called
def send_msg(input_area, receiver):
    msg = input_area.get()
    input_area.delete(0, 'end')
    if msg:
        if len(msg) > 0:
            if receiver == 'everyone':
                globals()['msg_win'].config(state='normal')
                globals()['msg_win'].insert('end', f'you: {msg}' + '\n')
                globals()['msg_win'].yview('end')
                globals()['msg_win'].config(state='disabled')
                protocol = f'GM -Option <username:{USERNAME}> -Option <message_len:{len(msg)}> -Option <message_body:{msg}>'
            else:
                globals()['msg_win'].config(state='normal')
                globals()['msg_win'].insert('end', f'you to {receiver}: {msg}' + '\n')
                globals()['msg_win'].yview('end')
                globals()['msg_win'].config(state='disabled')

                # private messages are encrypted
                key = str(randint(10000, 99999))
                hashed_key = Fernet(urlsafe_b64encode(md5(key.encode()).hexdigest().encode()))
                encoded_msg = hashed_key.encrypt(msg.encode()).decode()
                protocol = f'PM -Option <username:{USERNAME}> -Option <message_len:{len(encoded_msg)}>' \
                           f' -Option <to:{receiver}> -Option <message_body:{encoded_msg}> -Option <key:{key}>'

            s.send(protocol.encode())


# this function is called when the user selects the get_users button from the gui
def get_users():
    protocol = f'Users -Option <user:{USERNAME}>'
    s.send(protocol.encode())
    receive_msg()


# this function is called when the user selects the leave button from the gui. or after closing the window.
def leave():
    protocol = f'End -Option <id:{USERNAME}>'
    s.send(protocol.encode())
    s.close()
    exit(0)


if __name__ == '__main__':
    # print("Run main.py")
    main()

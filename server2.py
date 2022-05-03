from threading import Thread
from threading import Lock 
from tkinter import *
from queue import Queue
from datetime import datetime
import json, time, sys, socket, os


Queue = Queue() 
Lock = Lock()   
max_ip = 20
ip_list = []

class DOSPrevention(Thread):
    def __init__(self,s):
        Thread.__init__(self)
        self.s = s
        
    def run(self):
        host, port = self.s.getpeername()
        ip_list.append(host)
        dup = self.duplicate(host)
        if dup == 1:
            file_txt = open("attack_DDoS.txt",'a')
            t1 = str(datetime.now())
            file_txt.writelines(t1 + "\n")
            line = "DDOS attack is Detected: "
            file_txt.writelines(line)
            file_txt.writelines(host + "\n")
            file_txt.writelines("--------------------------------" + "\n")
            self.s.close()
        elif dup == 2:
            self.s.close()


    def duplicate(self,host):
        for host in ip_list:
            if ip_list.count(host) == max_ip:
                return 1
            elif ip_list.count(host) > max_ip:
                return 2
        return 3
        
class AcceptClient(Thread):

    def __init__(self):
        Thread.__init__(self)
        self.HOST = socket.gethostname()
        self.HOST_IP = socket.gethostbyname(HOST)
        self.LOGPORT = 6543 
        self.LOGADDR = (self.HOST_IP, self.LOGPORT)
        self.server_login = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_login.bind(self.LOGADDR)
        self.server_login.listen(5)  # Listens for 5 connections at max.

    def run (self):
        while True:
            client, client_address = self.server_login.accept()
            option = client.recv(BUFFER).decode("utf-8")
            if option == "register":
                self.accept_login(client, option)  
            elif option == "login":
                self.accept_login(client, option) 
            else:
                client.shutdown(socket.SHUT_WR)
            DOS_THREAD = DOSPrevention(client)
            DOS_THREAD.start()
        client.close()

    # Function to accept client requests and to get nickname and address
    # arguments - 0
    # returns - nothing
    def accept_login(self,client, option):
        client_name = client.recv(BUFFER).decode("utf-8")
        client_pass = client.recv(BUFFER).decode("utf-8")
        if option == "register":
            self.update_log_file(client_name, client_pass, client)
        elif option == "login":
            self.check_log_file(client_name, client_pass, client)
            
            
    def check_log_file(self ,name, password, client):
        """
        save the client address information in txt file and use temp file to log currently active users
        """
        list_of_files = os.listdir()
        if name in list_of_files:
            file1 = open(name, "r")
            verify = file1.read().splitlines()
            if password in verify:
                client.send(bytes("login success".encode("utf-8")))
                client.close()
                return
            else:
                client.send(bytes("password error".encode("utf-8")))
                self.accept_login(client)
        else:
            client.send(bytes("username error" .encode("utf-8")))
        self.accept_login(client)

    def update_log_file(self, name, password, client):

        current_directory = os.getcwd()
        users_list = os.listdir(current_directory)
        if name in users_list:
            client.send(bytes("username already exists".encode("utf-8")))
        else:
            file=open(name, "w")
            file.write(name+"\n")
            file.write(password+"\n")
            file.close()
            client.send(bytes("register success".encode("utf-8")))
            self.accept_login(client)

class HandleClient(Thread):
    global users, Lock, Queue

    def __init__(self):
        Thread.__init__(self)
        self.HOST = socket.gethostname()
        self.HOST_IP = socket.gethostbyname(self.HOST)
        self.CHATPORT = 3456  
        self.CHATADDR = (self.HOST_IP, self.CHATPORT)
        self.server_chat = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Function to handle connected clients requests to message and to broadcast messages
    # arguments - 1
    # returns - nothing
    def run(self):
        self.server_chat.bind(self.CHATADDR)
        self.server_chat.listen(5)  # Listens for 5 connections at max.
        broad = Thread(target=self.broadcast)
        broad.start()
        while True:
            conn, addr = self.server_chat.accept()
            str = Thread(target=self.join, args=(conn,addr))
            str.start()
        self.server_chat.close()

    def join(self, client2, client_address2):
            cname = client2.recv(BUFFER).decode("utf-8")
            for i in range(len(users)):
                if cname == users[i][1]:
                    cname = '' + cname + '_2'
            client2.send(cname.encode("utf-8"))
            users.append((client2, cname, client_address2))
            server_Log.config(state=NORMAL)
            server_Log.insert(INSERT, "New connection: ")
            server_Log.insert(INSERT, cname +"\n")
            server_Log.config(state=DISABLED)
            onliners = active_users()
            self.receive(onliners, client_address2)
            try:
                while True:
                    data = client2.recv(BUFFER).decode("utf-8")
                    if data == "{end}":
                        self.delUsers(client2, client_address2)
                        client2.close()
                    else:
                        self.receive(data, client_address2)
                self.client2.close()
            except:
                server_Log.config(state=NORMAL)
                server_Log.insert(INSERT, "Connection lost: ")
                server_Log.insert(INSERT, cname +"\n")
                server_Log.config(state=DISABLED)
                self.delUsers(client2, client_address2)
                client2.close()   

    def delUsers(self, client2, client_address2):
        a = 0
        for i in users:
            if i[0] == client2:
                users.pop(a)
                onliners = active_users()
                self.receive(onliners, client_address2)
                server_Log.config(state=NORMAL)
                server_Log.insert(INSERT, "Remaining online users: 0" + "\n")
                server_Log.insert(INSERT, onliners)
                server_Log.insert(INSERT, "\n")
                server_Log.config(state=DISABLED)
                break
            a += 1

    def broadcast(self):
        while True:
            if not Queue.empty():
                data = ''
                message = Queue.get()
                if isinstance(message[1], str):
                    for i in range(len(users)):
                        for j in range(len(users)):
                            if message[0] == users[j][2]:
                                data = " " + users[j][1] + "：" + message[1]
                                print(data)
                                print (users)
                                break
                        users[i][0].send(bytes(data, "utf-8"))
                if isinstance(message[1], list):  
                    data = json.dumps(message[1])
                    for i in range(len(users)):
                        try:
                            users[i][0].send(bytes(data, "utf-8"))
                        except:
                            pass

    def receive(self, data, client_address2 ):
        Lock.acquire()
        try:
            Queue.put((client_address2, data))
        finally:
            Lock.release()


def active_users():
    online = []
    for i in range(len(users)):
        online.append(users[i][1])
    return online

#define host address & port and bind the socket to those parameters
HOST = socket.gethostname()
HOST_IP = socket.gethostbyname(HOST)  
BUFFER = 1024

#define the array of client connected and there addresses
clients = {}
users = []
flags = {}
flags ["DOS"] = False
##server gui window configuration and place
root =Tk()
wintitle = 'Server v1.0\t' + HOST + ':'
root.geometry("400x400")
server_Log = Text(root, bd=0, bg="white", height="8", width="50", font="Arial")
server_Log.insert(END, "Waiting for clients connection...\n")
server_Log.config(state=DISABLED)
server_scrollbar = Scrollbar(root, command=server_Log.yview, cursor="heart")
server_Log['yscrollcommand']=server_scrollbar.set
server_Log.place(x=4,y=4, height=394, width=384)
server_scrollbar.place(x=388,y=4, height=394, width=10)

if __name__ == '__main__':
    ACCEPT_THREAD = AcceptClient()
    ACCEPT_THREAD.start()  # Starts the infinite loop.
    HANDLE_THREAD = HandleClient()
    HANDLE_THREAD.start()  # Starts the infinite loop.  
    root.mainloop()
    
    while True:
        time.sleep(1)
        if not ACCEPT_THREAD.is_alive():
            print("Chat connection lost...")
            sys.exit(0)





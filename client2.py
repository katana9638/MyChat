from threading import Thread
from tkinter import *
from tkinter.messagebox import showerror
from tkinter import filedialog
import socket,time,json,datetime

class MychatNetworkScreen(Tk):
    """
    The main GUI screen for creating and logging into accounts and specifying 
    what port and IP of the server you want to connect to.
    """
    def __init__(self, status):
        Tk.__init__(self)
        self.flags = status
        self.grid()
        self.geometry("150x200")
        self.title("Mychat")
        self.heading_lbl = Label(self, text = "Mychat Server")
        self.ip_lbl = Label(self, text = "Server IP: " )
        self.ip_ent = Entry(self)
        self.s_port_lbl = Label(self, text = "Login PORT: " )
        self.s_port_ent = Entry(self)
        self.c_port_lbl = Label(self, text = "Chat PORT: " )
        self.c_port_ent = Entry(self)
        self.done_but = Button(self, text = "Done", width = "8", height = "1", command = self.network_info)
        self.quit_but = Button(self, text= "Quit", width = "8", height = "1", command=self.destroy)

        self.heading_lbl.grid(row=0, column=0, columnspan=3, sticky=EW,padx=10)
        self.ip_lbl.grid(row=1, column=0,columnspan=3, sticky=EW,padx=10)
        self.ip_ent.grid(row=2, column=0,columnspan=3, sticky=EW,padx=10)
        self.s_port_lbl.grid(row=3, column=0,columnspan=3,sticky=EW,padx=10)
        self.s_port_ent.grid(row=4, column=0,columnspan=3,sticky=EW,padx=10)
        self.c_port_lbl.grid(row=5, column=0,columnspan=3,sticky=EW,padx=10)
        self.c_port_ent.grid(row=6, column=0,columnspan=3,sticky=EW,padx=10)
        self.done_but.grid(row=10, column=1,columnspan=1,sticky=EW)
        self.quit_but.grid(row=11, column=1,columnspan=1,sticky=EW)


    def network_info(self):
        global client_addr
        global host_addr
        global login_port
        global chat_port
        global addr

        host_addr = str(self.ip_ent.get())
        client_addr = socket.gethostbyname(socket.gethostname())
        login_port = (self.s_port_ent.get())
        chat_port = (self.c_port_ent.get())
        addr = (host_addr, login_port)

        self.flags["IP_flag"] = self.valid_ip(host_addr)
        self.flags["port_flag"] = self.valid_port( login_port, chat_port)

        if  self.flags["IP_flag"] & self.flags["port_flag"] == True:
            self.destroy()

    def valid_ip(self, IP):
        flag = False
        if IP.count(".") == 3:
            x = IP.split(".")
            y = [int(numeric_string) for numeric_string in x]
            for i in y:
                if(0 <= i <= 255):
                    flag = True
                    return flag
                else:
                    showerror("IP error")
                    flag = False
                    return flag

        else:
            showerror("IP error")
            flag = False
            return flag
        return flag

    def valid_port(self, port1, port2):
        flag = False
        x = [port1,port2]
        for i in x:
            if len(i) == 4 and i.isdigit():
                flag = True
                return flag
            else:
                showerror("PORT error")
                flag = False
                return flag
        return flag

class MychatLoginScreen(Tk):

    def __init__(self, status):
        Tk.__init__(self)
        self.flags = status
        self.login_start = Frame(self)
        self.login_start.grid()
        self.geometry("200x200")
        self.title("Mychat Login")
        #self.protocol("WM_DELETE_WINDOW", self.close_login)

        self.grab_set()
        self.login_but = Button(self.login_start, text = "Login", width = "10", height = "2", command = self.log_in)
        self.regi_but = Button(self.login_start, text = "Register", width = "10", height = "2", command = self.register)
        self.quit_but = Button(self.login_start, text= "Quit", width = "8", height = "1", command=self.close_login)

        self.login_but.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.regi_but.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.quit_but.grid(row=5, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
       
    def register(self):
        self.username = StringVar()
        self.password = StringVar()

        self.reg_screen = Toplevel(self.login_start)
        self.reg_screen.title("Register")
        self.reg_screen.geometry("220x250")
        self.reg_screen.grid()

        self.reg_lbl = Label(self.reg_screen, text = "Enter Details Below")
        self.new_user_lbl = Label(self.reg_screen, text = "Username *")
        self.username_entry = Entry(self.reg_screen, textvariable=self.username)
        self.new_pass_lbl = Label(self.reg_screen, text = "Password *")
        self.password_entry = Entry(self.reg_screen, textvariable = self.password)
        self.reg_but = Button(self.reg_screen, text = "Register", width = 10, height = 1, command = self.register_user)

        self.reg_lbl.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.new_user_lbl.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.username_entry.grid(row=5, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.new_pass_lbl.grid(row=7, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.password_entry.grid(row=9, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.reg_but.grid(row=11, column=1,columnspan=1,pady=10,padx=20,sticky=EW)

    def log_in(self):
        self.username_ver = StringVar()
        self.password_ver = StringVar()

        self.login_screen = Toplevel(self.login_start)
        self.login_screen.title("Login")
        self.login_screen.geometry("220x250") 

        self.log_lbl = Label(self.login_screen, text = "Enter Details Below")
        self.user_lbl = Label(self.login_screen, text = "Username *")
        self.username_entry2 = Entry(self.login_screen, textvariable=self.username_ver)
        self.pass_lbl = Label(self.login_screen, text = "Password *")
        self.password_entry2 = Entry(self.login_screen, textvariable= self.password_ver)
        self.log_but = Button(self.login_screen, text = "Login", width = 10, height = 1, command = self.login_user)

        self.log_lbl.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.user_lbl.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.username_entry2.grid(row=5, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.pass_lbl.grid(row=7, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.password_entry2.grid(row=9, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        self.log_but.grid(row=11, column=1,columnspan=1,pady=10,padx=40,sticky=EW)

    def register_user(self):
        self.username_info2 = self.username.get()
        self.password_info2 = self.password.get()
        sock_login.send(bytes("register", "utf-8"))
        time.sleep(1)
        sock_login.send(bytes(self.username_info2, "utf-8"))
        sock_login.send(bytes(self.password_info2, "utf-8"))
        message = sock_login.recv(BUFFER).decode("utf-8")
        if message == "username already exists":
            self.reg_suc_lbl = Label(self.reg_screen, text = "username already exists", fg = "blue", font = ("ariel", 12))
            self.reg_done_but = Button(self.reg_screen, text = "Done", command = lambda: self.reg_screen.destroy())
            self.reg_suc_lbl.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
            self.reg_done_but.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        else:
            self.reg_suc_lbl = Label(self.reg_screen, text = "Registered", fg = "blue", font = ("ariel", 12))
            self.reg_done_but = Button(self.reg_screen, text = "Done", command = lambda: self.reg_screen.destroy())
            self.reg_suc_lbl.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
            self.reg_done_but.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)

    def login_user(self):
        global username_info
        username_info = self.username_ver.get()
        self.password_info = self.password_ver.get()
        sock_login.send(bytes("login", "utf-8"))
        time.sleep(1)
        sock_login.send(bytes(username_info, "utf-8"))
        sock_login.send(bytes(self.password_info, "utf-8"))
        message = sock_login.recv(BUFFER).decode("utf-8")

        if message == "username error":
            self.reg_suc_lbl = Label(self.login_screen, text = "username error", fg = "blue", font = ("ariel", 12))
            self.reg_done_but = Button(self.login_screen, text = "Done", command = lambda: self.login_screen.destroy())
            self.reg_suc_lbl.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
            self.reg_done_but.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        elif message == "password error":
            self.reg_suc_lbl = Label(self.login_screen, text = "password error", fg = "blue", font = ("ariel", 12))
            self.reg_done_but = Button(self.login_screen, text = "Done", command = lambda: self.login_screen.destroy())
            self.reg_suc_lbl.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
            self.reg_done_but.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
        else:
            
            self.log_suc_lbl = Label(self.login_screen, text = "Login Success")
            self.log_done_but = Button(self.login_screen, text = "Done", command = self.close)
            self.log_suc_lbl.grid(row=1, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
            self.log_done_but.grid(row=3, column=1,columnspan=1,pady=10,padx=40,sticky=EW)
            sock_login.close()

    def close(self):
        self.flags["IP_flag"] = False
        self.flags["port_flag"] = False
        self.flags["chat_flag"] = True
        self.login_screen.destroy()
        self.login_start.destroy()

    def close_login(self):
        message = "{end}"
        sock_login.send(bytes(message, "utf-8"))
        sock_login.close()
        self.flags["IP_flag"] = False
        self.flags["port_flag"] = False
        self.flags["chat_flag"] = False
        self.login_start.destroy()

class ChatWindow(Tk):
    def __init__(self, status):
        Tk.__init__(self)   
        self.user = username_info
        self.count=0
        self.start = time.time()
        self.opt = "--GROUP--"
        self.users = []
        sock_chat.send(bytes(self.user, "utf-8"))
        self.user = sock_chat.recv(BUFFER).decode("utf-8")
        self.flags = status
        self.init_ui()

    def init_ui(self):
        self.title("Mychat")
        self.protocol("WM_DELETE_WINDOW", self.close_chat)
        self.geometry("480x500")

        #-----Chat Window---------------- 
        self.chatlog = Text(self, bg = "white", height="30", width="70", font=("Arial", 12),)
        self.chatlog.config(state=DISABLED)
        self.chat_scrollbar = Scrollbar(self, command=self.chatlog.yview, cursor="heart")
        self.chatlog['yscrollcommand'] = self.chat_scrollbar.set
        self.chatlog.tag_config('BROAD', background="white", foreground="red")
        self.chatlog.tag_config('PM', background="white", foreground="green")
        self.chatlog.tag_config('OWN', background="white", foreground="blue")
        self.chatlog.tag_config('OWNPM', background="white", foreground="orange")

        #Create the box to enter message
        self.msg_entry = Entry(self,bd=0, bg="white", width="29", font="Arial")
        self.msg_entry.bind("<Return>", lambda e:self.send())

        #key of message types
        self.key = Text(self, bg = "white", height="15", width="30", font=("Arial", 9),)
        self.key_lbl = Label(self, font=1, text='Message Type')
        self.key.tag_config('BROAD', background="white", foreground="red")
        self.key.tag_config('PM', background="white", foreground="green")
        self.key.tag_config('OWN', background="white", foreground="blue")
        self.key.tag_config('OWNPM', background="white", foreground="orange")
        self.key.config(state=NORMAL)
        self.key.insert(INSERT, "Received Group message"+"\n", "BROAD")
        self.key.insert(INSERT, "Received Private message"+"\n", "PM")
        self.key.insert(INSERT, "Sent Group message"+"\n", "OWN")
        self.key.insert(INSERT, "Sent Private message"+"\n", "OWNPM")
     
        #Create Online Friend List
        self.chat_frilist_lbl = Label(self, font=9, text='Friend List')
        self.friends = []
        self.fri_var = StringVar(self,value=self.friends)
        self.chat_frilist = Listbox(self)
        self.fri_scrollbar = Scrollbar(self,orient='vertical',command=self.chat_frilist.yview)
        self.chat_frilist['yscrollcommand'] = self.fri_scrollbar.set
        self.chat_frilist.bind('<ButtonRelease-1>', lambda e:self.private())
        
        #Create the Button to send message and send txt files
        self.chat_Sendbttn = Button(self, font=12, text="Send", width="12", height="5", command=self.send)
        self.chat_filebttn = Button(self, font=12, text="Upload", width="12", height="5", command=self.file_send)

        self.chatlog.place(x=6,y=6, height=386, width=290)
        self.key.place(x=310,y=280, height=110, width=155)
        self.key_lbl.place(x=320, y=240, height=23, width=140)
        self.chat_scrollbar.place(x=295,y=10, height=386, width=5)
        self.msg_entry.place(x=6, y=401, height=90, width=290)
        self.chat_frilist_lbl.place(x=320, y=3, height=23, width=120)
        self.chat_frilist.place(x=320, y=30, height=200, width=120)
        self.fri_scrollbar.place(x=445, y=30, height=200, width=5)
        self.chat_Sendbttn.place(x=310, y=401, height=45)
        self.chat_filebttn.place(x=310, y=445, height=45)

    def send(self): 
        """
        Handles sending of messages.
        """
        self.users.append("--GROUP--")
        if self.opt not in self.users:
            showerror('Send error', message='There is nobody to talk to!')
            return
        if self.opt == self.user:
            showerror('Send error', message='Cannot talk with yourself in private!')
            return
        msg = self.msg_entry.get()
        send_message = msg + ':;' + self.user + ':;' + self.opt + ':;' + date_string()
        self.start = time.time()
        sock_chat.send(bytes(send_message, "utf-8"))

    def close_chat(self):
        """
        When the application is to be terminated
        """
        sock_chat.send(bytes("{end}", "utf-8"))
        self.flags["IP_flag"] = False
        self.flags["port_flag"] = False
        self.flags["chat_flag"] = False
        self.destroy()

    def private(self):
        # Get user name
        indexs = self.chat_frilist.curselection()
        index = indexs[0]
        if index > 0:
            self.opt = self.chat_frilist.get(index)
            if self.opt == "--GROUP--":
                self.title(self.user)
                return
            ti = self.user + '  -->  ' + self.opt
            self.title(ti)

    def file_send(self):
        """
        Handles sending of files.
        """
        self.iconbitmap('c:')
        self.filename = filedialog.askopenfilename(initialdir="c:", title ="Upload", filetypes=(("txt files", "*.txt"),("all files", "*.*")))
        path = self.filename
        #path = "C:/Users/georg/OneDrive/Documents/UNI work year 3/Individual Project/MyChat/c.txt"

        file = open(path, "r")
        file_data = file.read(BUFFER)
        self.opt = "file"
        file_message = file_data + ':;' + self.user + ':;' + self.opt + ':;' + date_string()
        self.start = time.time()
        sock_chat.send(bytes(file_message, "utf-8"))
        file.close()

    def file_receive(self, name, file_data):
        self.file_screen = Toplevel(self)
        self.file_screen.title("Login")
        self.file_screen.geometry("250x200") 

        self.file_lbl = Label(self.file_screen, text='Do you want to download file from:' + name + "?")
        self.yesbtn = Button(self.file_screen, font=1, text="yes", width="8", height="1", command=lambda: self.download_file(name, file_data))
        self.nobtn = Button(self.file_screen, font=1, text="no", width="8", height="1", command=lambda: self.file_screen.destroy())

        self.file_lbl.grid(row=0, column=0, columnspan=3, sticky=EW,padx=10)
        self.yesbtn.grid(row=10, column=1,columnspan=1,sticky=EW)
        self.nobtn.grid(row=11, column=1,columnspan=1,sticky=EW)
        self.download_file(name, file_data)

    def download_file(self, name,file_data):
        file_data = bytes(file_data, "utf-8")
        filename = (name + "_text")
        file = open(filename, "wb")
        file.write(file_data)
        file.close()
        #self.file_screen.destroy()
        return

        
class Receiving(Thread):
    """ 
    Runs with the chat app and constantly checks for incoming messages from server
    """
    def __init__(self, app):
        Thread.__init__(self)
        self.app = app
        self.duration = 0.0

    def run(self):
        while True:
            message = sock_chat.recv(1024).decode("utf-8")
            #self.duration += time.time() - self.app.start
            #print(self.duration*pow(10, 6)/1)
            try:
                """ 
                Load the connection information and put them on friend list
                """
                message = json.loads(message)
                self.app.users = message
                self.app.chat_frilist.delete(0, END)
                number = ('   Users online: ' + str(len(message)))
                self.app.chat_frilist.insert(END, number)
                self.app.chat_frilist.itemconfig(END, fg='green', bg="#f0f0ff")
                self.app.chat_frilist.insert(END, "--GROUP--")
                self.app.chat_frilist.itemconfig(END, fg='green')
                for i in range(len(message)):
                    self.app.chat_frilist.insert(END, (message[i]))
                    self.app.chat_frilist.itemconfig(END, fg='green')
            except:
                data = message.split(':;')
                data1 = data[0].strip()  #sender+msg
                data2 = data[1]  #sender
                data3 = data[2] #option
                data4 = data[3] #timestamp
                msg = data1.split('：')[1] #message

                self.app.chatlog.config(state=NORMAL)
                if data3 == "file":
                    self.app.file_receive(data2,msg)
                    #self.duration += time.time() - self.app.start
                    #print(self.duration*pow(10, 6)/1)
                    self.app.chatlog.insert(INSERT, data4)
                    self.app.chatlog.insert(INSERT, "file sent by: ")
                    self.app.chatlog.insert(INSERT, data2)
                    self.app.chatlog.insert(INSERT, "\n")
                if data2 == self.app.user and data3 == "--GROUP--":
                    #self.duration += time.time() - self.app.start
                    #print(self.duration*pow(10, 6)/1)
                    self.app.chatlog.insert(INSERT, data4)
                    self.app.chatlog.insert(INSERT, data1, "OWN")
                    self.app.chatlog.insert(INSERT, "\n")
                if data3 == "--GROUP--" and data2 != self.app.user :
                    self.app.chatlog.insert(INSERT, data4)
                    self.app.chatlog.insert(INSERT, data1, "BROAD")
                    self.app.chatlog.insert(INSERT, "\n")
                if (data3 != "--GROUP--" and data3 != "file" and data3 != self.app.user) and data2 == self.app.user:
                    self.app.chatlog.insert(INSERT, data4)
                    self.app.chatlog.insert(INSERT, data1, "OWNPM")
                    self.app.chatlog.insert(INSERT, "\n")
                if data3 == self.app.user:
                    self.app.chatlog.insert(INSERT, data4)
                    self.app.chatlog.insert(INSERT, data1, "PM")
                    self.app.chatlog.insert(INSERT, "\n")
                self.app.chatlog.see(END)  
                self.app.chatlog.config(state=DISABLED)

def server_connect(PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host_addr, int(PORT)))
    return sock

def date_string():
    a = datetime.datetime.now()
    b = [a.year, a.month, a.day, a.hour, a.minute, a.second]
    c = ["a"] *6
    for i in range(len(b)):
        if len(str(b[i])) == 1:
            c[i] = ("0" + str(b[i]))
        else:
            c[i] = str(b[i])
    d = ("(%s/%s/%s %s:%s:%s) " % (c[0],c[1],c[2],c[3],c[4],c[5]))
    return d


global sock_login
global sock_chat
BUFFER = 763

flags = {}
flags ["active"] = True
flags ["IP_flag"] = False
flags ["port_flag"] = False
flags ["chat_flag"] = False
flags ["recv_flag"] = False

chatapp = MychatNetworkScreen(flags)
mainloop()

while flags ["active"] == True:
    if flags["IP_flag"] & flags["port_flag"] == True:
        try:
            sock_login = server_connect(login_port)
            sock_login.settimeout(10)

        except socket.error:
            flags ["IP_flag"] = False
            flags ["active"] = False
            flags ["port_flag"] = False
            flags ["chat_flag"] = False
            flags ["recv_flag"] = False
            showerror("socket error")

    if flags["IP_flag"] & flags["port_flag"] == True:

        log = MychatLoginScreen(flags)
        mainloop()

    if flags["chat_flag"] == True:
        try:
            sock_chat = server_connect(chat_port)

        except socket.error:
            flags ["IP_flag"] = False
            flags ["active"] = False
            flags ["port_flag"] = False
            flags ["chat_flag"] = False
            flags ["recv_flag"] = False
            showerror("socket error")

        if flags["chat_flag"] == True:    
            chat_win = ChatWindow(flags)
            rcv = Receiving(chat_win)
            rcv.start()
            mainloop()

    
 

import nmap
import socket,sys,threading,time
from tkinter import *
 
# ==== Scan Vars ====
init_port_s = 1
init_port_f = 1024
temp=0
temp2=''
log = []
ports = []
target = 'localhost'
scanner=nmap.PortScanner()
 
# ==== Scanning Functions ====
def scanPort(target, port):
    try:
        s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        c= s.connect_ex((target, port))
        if c== 0:
            m = ' Port %d \t[open]' % (port,)
            log.append(m)
            ports.append(port)
            listbox.insert("end", str(m))
            updateResult()
        s.close()
    except OSError: print('> Too many open sockets. Port ' + str(port))
    except:
        c.close()
        s.close()
        sys.exit()
    sys.exit()
     

 
def scanUDP(ip_addr):
    version=f'Nmap Version: ,{scanner.nmap_version()}'
    scanner.scan(ip_addr, '1-100', '-v -sU')
    scinfo=f'{scanner.scaninfo()}'
    ip_status=f'Ip Status: , {scanner[ip_addr].state()}'
    p_rotocol=f'protocols:,{scanner[ip_addr].all_protocols()}'
    # o_port="Open Ports: ", scanner[ip_addr]['udp'].keys()
    log.append([version,scinfo,ip_status,p_rotocol])
    updateResult()



def comprehensiveScan(ip_addr):
    version=f'\nNmap Version: , {scanner.nmap_version()}'
    # sS for SYN scan, sv probe open ports to determine what service and version they are running on
    # O determine OS type, A tells Nmap to make an effort in identifying the target OS
    scanner.scan(ip_addr, '1-100', '-v -sS -sV -sC -A -O')
    scinfo=scanner.scaninfo()
    ip_status=f'Ip Status: , {scanner[ip_addr].state()}'
    p_rotocol=f'protocols:,{scanner[ip_addr].all_protocols()}\n'
    # print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    log.append([version,scinfo,ip_status,p_rotocol])
    updateResult()

def OSDetection(ip_addr):
    scinfo=scanner.scan("127.0.0.1", arguments="-O")['scan']['127.0.0.1']['osmatch']
    log.append(scinfo)
    updateResult()

def pingScan(ip_addr):
    scanner.scan(hosts=f'{ip_addr}/24', arguments='-n -sP -PE -PA21,23,80,3389')
    hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
    for host, status in hosts_list:
        log.append('{0}:{1}'.format(host, status))
    updateResult()


def startScan():
    global ports, log, target, init_port_f
    var2=run_function()
    clearScan()
    log = []
    ports = []
    # Get ports ranges from GUI
    init_port_s = int(L24.get())
    init_port_f = int(L25.get())
    # Start writing the log file
    log.append('------------> Network Security Scanner <-----------')
    log.append('\n')
    log.append(' Target:\t' + str(target))
     
    target = socket.gethostbyname(str(L22.get()))
    log.append(' IP Adr.:\t' + str(target))
    log.append(' Ports: \t[ ' + str(init_port_s) + ' / ' + str(init_port_f) + ' ]')
    log.append('\n')
    if(var2==1):
    # Lets start scanning ports!
        while init_port_s <= init_port_f:
            try:
                scan = threading.Thread(target=scanPort, args=(target, init_port_s))
                scan.setDaemon(True)
                scan.start()
            except: time.sleep(0.01)
            init_port_s += 1
    elif(var2==2):
        scanUDP(target)
    elif(var2==3):
        comprehensiveScan(target)
    elif(var2==4):
        OSDetection(target)
    elif(var2==5):
        pingScan(target)
    
         
def saveScan():
    global log, target, ports, init_port_f
    # log[5] = " Result:\t[ " + str(len(ports)) + " / " + str(init_port_f) + " ]\n"
    with open('portscan-'+str(target)+'.txt', mode='wt', encoding='utf-8') as myfile:
            myfile.write(('\n').join(map(str,log)))
 
def clearScan():
    listbox.delete(0, 'end')

def option_select():
    temp2=values.get()
    return temp2

def run_function():
    var1=option_select()
    if(var1=='SYN ACK Scan'):
        temp=1

    elif(var1=='UDP Scan'):
        temp=2

    elif(var1=='Comprehensive Scan'):
        temp=3

    elif(var1=='OS Detection'):
        temp=4
    
    elif(var1=='Ping Scan'):
        temp=5
        
    return temp

def updateResult():
    var4=run_function()
    if(var4==1):
        message = " [ " + str(len(ports)) + " / " + str(init_port_f) + " ] ~ " + str(target)
        L27.configure(text = message)

    elif(var4==2):
        L27.configure(text = log)
    elif(var4==3):
        L27.configure(text = log)
    elif(var4==4):
        L27.configure(text = log)
    elif(var4==5):
        L27.configure(text = log)

 
# ==== GUI ====
gui = Tk()
gui.title('Port Scanner')
gui.geometry("1000x600+250+100")
 
# ==== Colors ====
object_color = '#fafcfc'
background = '#19191a'
foreground = '#f7fbfc'
 
gui.tk_setPalette(background=background, foreground=object_color, activeBackground=foreground,activeForeground=background, highlightColor=object_color, highlightBackground=object_color)
 

 
# === options ===

values=StringVar(gui)
values.set("Choose...")
L01 = Label(gui, text = "Scanning Method")
L01.place(x = 16, y = 40)
L02=OptionMenu(gui,values, 'SYN ACK Scan','UDP Scan','Comprehensive Scan','OS Detection','Ping Scan')

L02.place(x = 180, y = 40)


# ==== Labels ====
L11 = Label(gui, text = "Network Security Scanner",  font=("Helvetica", 16, 'underline'))
L11.place(x = 400, y = 10)

L21 = Label(gui, text = "Target: ")
L21.place(x = 16, y = 90)
 
L22 = Entry(gui, text = "localhost")
L22.place(x = 180, y = 90)
L22.insert(0, "localhost")
 
L23 = Label(gui, text = "Ports: ")
L23.place(x = 16, y = 158)
 
L24 = Entry(gui, text = "1")
L24.place(x = 180, y = 158, width = 95)
L24.insert(0, "1")
 
L25 = Entry(gui, text = "1024")
L25.place(x = 290, y = 158, width = 95)
L25.insert(0, "8080")
 
L26 = Label(gui, text = "Results: ")
L26.place(x = 16, y = 220)
L27 = Label(gui, text = "[ Start... ]")
L27.place(x = 180, y = 220)
 
# ==== Ports list ====
frame = Frame(gui)
frame.place(x = 16, y = 275, width = 970, height = 215)
listbox = Listbox(frame, width = 180, height = 6)
listbox.place(x = 0, y = 0)
listbox.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)
 
# ==== Buttons / Scans ====
# var3=run_function()
# if(var3==1):
#     temp3=

B11 = Button(gui, text = "Start Scan", command=startScan)
B11.place(x = 16, y = 500, width = 170)
B21 = Button(gui, text = "Save Result", command=saveScan)
B21.place(x = 800, y = 500, width = 170)
 
# ==== Start GUI ====
gui.mainloop()
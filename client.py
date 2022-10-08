import socket

s = socket.socket()

host = socket.gethostname()
port = 1234
ip= socket.gethostbyname()
print(ip)

s.connect((host, port))
print(s.recv(1024))



#https://www.pythonpool.com/python-nmap/
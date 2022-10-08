import socket

s = socket.socket()

host = socket.gethostname()
port = 5343
ip= socket.gethostbyname(host)
print(ip)

s.connect((host, port))
print(s.recv(1024))




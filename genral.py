import os

def create_direct(directory):               #Function creates a directory
    if not os.path.exists(directory):
        os.makedirs(directory)

def write(path,data):                       #Function that write your data
    f = open(path,'w')
    f.write(data)
    f.close()


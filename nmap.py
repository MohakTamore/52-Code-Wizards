import os

def get_nmap(options,ip):
    command = "nmap " + options + " " + ip
    response=os.popen(command)
    result=str(response.read())
    return result
print(get_nmap('-F','192.168.0.107'))

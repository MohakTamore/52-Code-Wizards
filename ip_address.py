import os

def get_ip_address(url):
    command = "nslookup " + url
    process=os.popen(command)
    result=str(process.read())
    mark=result.find('Address') +54
    return result[mark:].splitlines()[0]
get_ip_address('vcet.edu.in')


from tld import get_fld

def get_domain_name(url):                           #This function will return first level domain from domain provided 
    domain_name = get_fld(url)
    return domain_name


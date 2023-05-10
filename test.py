import requests
# use this for website detection works well with facebook not so much others.
def get_asn_from_ip(ip):
    x = requests.get(f"https://ipinfo.io/{ip}/json?token=94b2b26ca36876")
    y = x.json()
    print (y)

get_asn_from_ip("195.195.10.65")
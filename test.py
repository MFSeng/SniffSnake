import requests
# use this for website detection works well with facebook not so much others.
def get_asn_from_ip(ip):
    x = requests.get(f"https://ipinfo.io/{ip}/json")
    y = x.json()
    print (y)

get_asn_from_ip("10.83.81.23")
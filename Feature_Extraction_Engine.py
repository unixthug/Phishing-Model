import re
import requests # sends HHTP requests to a server and recieves response easier
import whois # allows users to retrieve and parse WHOIS data for a given domain
import ssl #  provides access to Transport Layer Security encryption and peer authentication facilities for network sockets
import socket # allowing programs to send and receive data over a network
from urllib.parse import urlparse

def extract_url_features(url): # I can explain this just ask me tbh I aint writing all dat
    parsed = urlparse(url)

    features = {
          "url_length": len(url),
        "domain_length": len(parsed.netloc),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(c in "@%$;#&?" for c in url),
        "num_subdomains": parsed.netloc.count("."),
        "uses_https": int(parsed.scheme == "https"),
    }

    return features

#this next func is to get domain age and registar info which can be major phishing indicators

def extract_whois_features(domain):
    try:
        info = whois.whois(domain)

        #domain age
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        #checks if its a list then picks the first one

        import datetime
        domain_age_days = (datetime.datetime.now() - creation_date).days
        #calcs domain age in days for easy to understand detection

        return { 
            "domain_age_days" : domain_age_days,
            "registrar": str(info.registrar)
        }
        #this is a number and a string for registrar for the ML training

    except: #
        return{
            "domain_age_days": -1,
            "registrar": "unknown"
        }
    #this is for fails just in case so the ML knows nothing could be found

#now we can get the SSL cert info 

def extract_ssl_features(domain):
    ctx = ssl.create_default_context() #creates a SSL enviroment 

    try:   
        #creates socket then wraps it in ssl then tries to connet to the domains https port 
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
        #this stuff is important cause some phishing sites evidently block port 443 and use http only and have broken certificates
        return{
             "ssl_valid": 1,
                "ssl_issuer": cert.get("issuer", "unknown"),
            }
    except:
        return {
            "ssl_valid": 0,
            "ssl_issuer": "none",
        }
# main extract pipeline just combines the 3 features for the phishing detection - I REALLY WANT TO PLAY STARDEW RN
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {}
    
    # 1. URL lexical features
    features.update(extract_url_features(url))

    # 2. WHOIS features
    features.update(extract_whois_features(domain))

    # 3. SSL certificate features
    features.update(extract_ssl_features(domain))

    return features


#chatgpt came up with this example template for us to test urls cause I def forgot about making a main
if __name__ == "__main__":
    url = "http://185.244.25.91/secure/login/verify"
    feats = extract_features(url)
    print(feats)
    
import re   #used to see if model url already has http or not to help us speed up the model
import whois #gets the domain info like the date it was made and the registar
import ssl #used to check certs 
import socket # double check for more certs
import ipaddress # checks for ip vs domain
from urllib.parse import urlparse # this is the important one to for us to send readable stuff to the model


def normalize_url(url: str) -> str:
   #function to fix urls before it makes it to the parser based on some patterns found online
    if url is None: #ngl this just incase so it wont crash
        return ""

    url = url.strip() #removes whitespace

    # Common defang patterns found in security reports
    url = url.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    url = url.replace("[://]", "://")

    # removes remaining brackets to avoid urllib treating it like IPv6 host syntax or  else more false positives
    url = url.replace("[", "").replace("]", "")

    # Ensure scheme exists so urlparse() populates netloc/hostname correctly 
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    return url


def is_ip_address(value: str) -> bool: #checks for ip address
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def safe_hostname(parsed) -> str:
    # extracts hostname from parsed url without breaking it
    return parsed.hostname or ""



def extract_url_features(url: str): #dis one for da lexical and structral features of da url
    parsed = urlparse(url)
    host = safe_hostname(parsed)

    features = {
        "url_length": len(url),
        "domain_length": len(host),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(c in "@%$;#&?" for c in url),
        "num_subdomains": host.count(".") if host else 0,
        "uses_https": int(parsed.scheme.lower() == "https"),
    }
    return features


def extract_whois_features(domain: str): 
    
    try:
        if not domain or is_ip_address(domain): #skips the lookup if no domain or ip address is found
            return {"domain_age_days": -1, "registrar": "unknown"}

        info = whois.whois(domain)

        creation_date = getattr(info, "creation_date", None)
        if isinstance(creation_date, list) and creation_date: #just inncase there is multiple cration dates
            creation_date = creation_date[0]

        if not creation_date: 
            domain_age_days = -1
        else:
            import datetime
            # some whois libs return date or datetime; datetime handles both
            domain_age_days = (datetime.datetime.now() - creation_date).days

        registrar = getattr(info, "registrar", None)
        if registrar is None:
            registrar = "unknown"

        return {
            "domain_age_days": int(domain_age_days),
            "registrar": str(registrar),
        }

    except Exception: #just incase of error wont break everything else
        return {
            "domain_age_days": -1,
            "registrar": "unknown",
        }


def extract_ssl_features(domain: str):
    
    try:
        if not domain:
            return {"ssl_valid": 0, "ssl_issuer": "none"}

        # Create SSL context
        ctx = ssl.create_default_context()

        # Use a timeout so it doesn't hang on dead hosts
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = cert.get("issuer", None)
        issuer_str = str(issuer) if issuer else "unknown"
        #extracts and normalizes the SSl cert
        return {
            "ssl_valid": 1,
            "ssl_issuer": issuer_str,
        }

    except Exception:
        return {
            "ssl_valid": 0,
            "ssl_issuer": "none",
        }



def extract_features(url: str):
   
    url = normalize_url(url)   # will crash if not parsed learned the hard way

    parsed = urlparse(url)
    domain = safe_hostname(parsed)

    features = {}
    features.update(extract_url_features(url))
    features.update(extract_whois_features(domain))
    features.update(extract_ssl_features(domain))

    return features




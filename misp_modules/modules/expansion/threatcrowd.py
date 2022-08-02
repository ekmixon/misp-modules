import json
import requests
import re

misperrors = {'error': 'Error'}
mispattributes = {'input': ["hostname", "domain", "ip-src", "ip-dst", "md5", "sha1", "sha256", "sha512", "whois-registrant-email"],
                  'output': ["domain", "ip-src", "ip-dst", "text", "md5", "sha1", "sha256", "sha512", "hostname", "whois-registrant-email"]
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'chrisdoman',
              'description': 'Get information from ThreatCrowd',
              'module-type': ['expansion']}

moduleconfig = []


# Avoid adding windows update to enrichment etc.
def isBlacklisted(value):
    blacklist = ['8.8.8.8', '255.255.255.255', '192.168.56.', 'time.windows.com']

    return any(value in b for b in blacklist)


def valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))


def valid_domain(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def valid_email(email):
    return bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", email))


def handler(q=False):
    if q is False:
        return False

    q = json.loads(q)

    r = {"results": []}

    if "ip-src" in q:
        r["results"] += getIP(q["ip-src"])
    if "ip-dst" in q:
        r["results"] += getIP(q["ip-dst"])
    if "domain" in q:
        r["results"] += getDomain(q["domain"])
    if 'hostname' in q:
        r["results"] += getDomain(q['hostname'])
    if 'md5' in q:
        r["results"] += getHash(q['md5'])
    if 'sha1' in q:
        r["results"] += getHash(q['sha1'])
    if 'sha256' in q:
        r["results"] += getHash(q['sha256'])
    if 'sha512' in q:
        r["results"] += getHash(q['sha512'])
    if 'whois-registrant-email' in q:
        r["results"] += getEmail(q['whois-registrant-email'])

    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
    return r


def getHash(hash):

    ret = []
    req = json.loads(
        requests.get(
            f"https://www.threatcrowd.org/searchApi/v2/file/report/?resource={hash}"
        ).text
    )


    if "domains" in req:
        domains = req["domains"]
        ret.extend(
            {"types": ["hostname"], "values": [domain]}
            for domain in domains
            if not isBlacklisted(domain) and valid_domain(domain)
        )

    if "ips" in req:
        ips = req["ips"]
        ret.extend(
            {"types": ["ip-dst"], "values": [ip]}
            for ip in ips
            if not isBlacklisted(ip)
        )

    return ret


def getIP(ip):
    ret = []
    req = json.loads(
        requests.get(
            f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}"
        ).text
    )


    if "resolutions" in req:
        ret.extend(
            {"types": ["hostname"], "values": [dns["domain"]]}
            for dns in req["resolutions"]
            if "domain" in dns and valid_domain(dns["domain"])
        )

    if "hashes" in req:
        ret.extend({"types": ["md5"], "values": [hash]} for hash in req["hashes"])
    return ret


def getEmail(email):
    ret = []
    j = requests.get(
        f"https://www.threatcrowd.org/searchApi/v2/email/report/?email={email}"
    ).text

    req = json.loads(j)

    if "domains" in req:
        domains = req["domains"]
        ret.extend(
            {"types": ["hostname"], "values": [domain]}
            for domain in domains
            if not isBlacklisted(domain) and valid_domain(domain)
        )

    return ret


def getDomain(domain):

    ret = []
    req = json.loads(
        requests.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        ).text
    )


    if "resolutions" in req:
        ret.extend(
            {"types": ["ip-dst"], "values": [dns["ip_address"]]}
            for dns in req["resolutions"]
            if "ip_address" in dns
        )

    if "emails" in req:
        ret.extend(
            {"types": ["whois-registrant-email"], "values": [email]}
            for email in req["emails"]
        )

    if "hashes" in req:
        ret.extend({"types": ["md5"], "values": [hash]} for hash in req["hashes"])
    return ret


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

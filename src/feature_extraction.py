import re
from urllib.parse import urlparse
import tldextract
from collections import Counter
from math import log2
SCHEME = 0
NETLOC = 1
SUBDOMAIN = 2
DOMAIN = 3
SUFFIX = 4
PATH = 5
PARAMS = 6
QUERY = 7
FRAGMENT = 8

def extract_url(url):
    url = str(url).strip()
    url = re.sub(r'([a-zA-Z0-9\-\+\.]+:(?!//))[/]*', r'\1//', url)
    extracted = tldextract.extract(url)
    parsed_origin = urlparse(url)
    if not parsed_origin.scheme and not url.startswith("//"):
        temp_url = "//" + url
        parsed_working = urlparse(temp_url)
    else:
        parsed_working = parsed_origin
    parts = [parsed_origin.scheme,
             parsed_working.netloc,
             extracted.subdomain,
             extracted.domain,
             extracted.suffix,
             parsed_working.path,
             parsed_working.params,
             parsed_working.query,
             parsed_working.fragment
             ]
    return parts

def Shannon_entropy(data):
    if not data:
        return 0
    char_count = Counter(data)
    l = len(data)
    s = sum(c*log2(c) for c in char_count.values())
    return log2(l) - s/l

def has_part(parts, index):
    if not parts[index]:
        return 0
    return 1

def part_length(parts, index):
    return len(parts[index])

def part_entropy(parts, index):
    return Shannon_entropy(parts[index])



url1 = "http://www.lebensmittel-ueberwachung.de/index.php/aktuelles.1"
parts1 = extract_url(url1)
print(parts1)
print(has_part(parts1, SCHEME))
print(has_part(parts1, FRAGMENT))
print(parts1[NETLOC])
print(part_entropy(parts1, NETLOC))
print(part_length(parts1, FRAGMENT))
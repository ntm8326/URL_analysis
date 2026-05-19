import re
from urllib.parse import urlparse
import tldextract
from collections import Counter
from math import log2

def url_length(url):
    return len(url)

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

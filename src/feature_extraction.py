import re
from urllib.parse import urlparse
import tldextract

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


url1 = "facebook.com"
url2 = "http://www.ikenmijnkunst.nl/index.php/exposities/exposities-2006"
url3 ="http://www.habbocreditos4.t83.net/#/hc-y-vip/4553149448"
url4 = "http:faceb00k.com"
print(extract_url(url4))
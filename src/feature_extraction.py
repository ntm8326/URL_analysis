from urllib.parse import urlparse
import tldextract

def url_length(url):
    return len(url)

def extract_url(url):
    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)
    if len(parsed_url.scheme) == 0:
        url = "http://" + url
        return extract_url(url)
    parts_array = [
        parsed_url.scheme,
        parsed_url.netloc,
        extracted.subdomain,
        extracted.domain,
        extracted.suffix,
        parsed_url.path,
        parsed_url.query
    ]
    return parts_array

url1 = "facebook.com"
url2 = "http://www.ikenmijnkunst.nl/index.php/exposities/exposities-2006"
print(extract_url(url1))
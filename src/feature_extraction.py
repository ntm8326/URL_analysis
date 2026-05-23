import re
from urllib.parse import urlparse, unquote_plus
import tldextract
from collections import Counter
from math import log2, floor
import ipaddress
from rapidfuzz.distance import Levenshtein
from rapidfuzz.distance.DamerauLevenshtein_py import similarity

SCHEME = 0
NETLOC = 1
SUBDOMAIN = 2
DOMAIN = 3
SUFFIX = 4
PATH = 5
PARAMS = 6
QUERY = 7
FRAGMENT = 8
def fully_decode(data):
    if not data:
        return ""
    current = str(data)

    while True:
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current = decoded

    return current
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

    decoded_path = fully_decode(parsed_working.path)
    decoded_params = fully_decode(parsed_working.params)
    decoded_query = fully_decode(parsed_working.query)
    decoded_fragment = fully_decode(parsed_working.fragment)

    parts = [parsed_origin.scheme,
             parsed_working.netloc,
             extracted.subdomain,
             extracted.domain,
             extracted.suffix,
             decoded_path,
             decoded_params,
             decoded_query,
             decoded_fragment
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
def digit_ratio(data):
    if not data:
        return 0.0
    return sum(c.isdigit() for c in data) / len(data)
def dot_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '.')
def hyphen_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '-')
def hash_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '#')
def percent_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '%')
def slash_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '/')
def at_sign_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '@')
def ampersand_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '&')
def equal_count(data):
    if not data:
        return 0
    return sum(1 for c in data if c == '=')
def strange_char_count(data):
    if not data:
        return 0
    valid_pattern = r'[^a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]'
    strange_chars = re.findall(valid_pattern, data)
    return len(strange_chars)
def is_ip(data):
    try:
        ipaddress.ip_address(data)
        return 1
    except ValueError:
        return 0
def levenshtein(data, file_whitelist):
    threshold = max(1, floor(len(data)/7))
    highest_score = 0
    most_similar_domain = ""
    try:
        with open(file_whitelist, 'r', encoding = 'utf-8') as file:
            for line in file:
                check_domain = line.strip()
                if not check_domain:
                    continue
                extracted = extract_url(check_domain)
                host_domain = f"{extracted[DOMAIN]}.{extracted[SUFFIX]}"
                len_diff = abs(len(data) - len(host_domain))
                if len_diff > threshold:
                    continue
                distain = Levenshtein.distance(data, host_domain, score_cutoff = threshold)
                if distain <= threshold:
                    current_score = Levenshtein.normalized_similarity(data, host_domain)
                    if current_score > highest_score:
                        highest_score = current_score
                        most_similar_domain = host_domain

        return {
            "normalized similarity": highest_score,
            "domain": most_similar_domain
        }
    except FileNotFoundError:
        return {
            "normalized similarity": 0.0,
            "domain": ""
        }

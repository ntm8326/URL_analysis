import re
from urllib.parse import urlparse, unquote_plus
import tldextract
from collections import Counter
from math import log2, floor
import ipaddress
from rapidfuzz.distance import Levenshtein
SCHEME = 0
NETLOC = 1
USERNAME = 2
PASSWORD = 3
PORT = 4
SUBDOMAIN = 5
DOMAIN = 6
SUFFIX = 7
PATH = 8
PARAMS = 9
QUERY = 10
FRAGMENT = 11
VOWELS = set('aeiouAEIOU')
SUSPICIOUS_KEYWORDS = {
    # authentication
    'login', 'signin', 'sign-in', 'log-in',
    'logout', 'signout',
    # account
    'account', 'myaccount', 'profile', 'user',
    # security
    'secure', 'security', 'verify', 'verification',
    'validate', 'validation', 'confirm', 'confirmation',
    # financial
    'banking', 'payment', 'checkout', 'billing',
    'invoice', 'wallet', 'transaction',
    # urgency
    'update', 'urgent', 'alert', 'warning', 'notice',
    'suspend', 'suspended', 'limited', 'unlock',
    # support
    'support', 'helpdesk', 'recover', 'recovery',
    'reset', 'password', 'credential',
    # webmail
    'webmail', 'outlook', 'office365', 'cpanel',
}
url_structure = [SCHEME, NETLOC, PATH, QUERY, FRAGMENT]

def fully_decode(data : str) -> str:
    if not data:
        return ""
    current = str(data)
    while True:
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current = decoded
    return current
def normalize_url(url: str) -> str:
    if re.match(r'^[a-zA-Z][a-zA-Z0-9\+\-\.]*://', url):
        return url
    if url.startswith('//'):
        return url
    return '//' + url
def extract_url(url : str) -> list:
    url = str(url).strip()
    normalized = normalize_url(url)
    extracted = tldextract.extract(normalized)
    parsed = urlparse(normalized)
    scheme = urlparse(url).scheme if '://' in url else ''
    decoded_username = fully_decode(parsed.username)
    decoded_password = fully_decode(parsed.password)
    decoded_path = fully_decode(parsed.path)
    decoded_params = fully_decode(parsed.params)
    decoded_query = fully_decode(parsed.query)
    decoded_fragment = fully_decode(parsed.fragment)
    parts = [scheme,
             parsed.netloc,
             decoded_username,
             decoded_password,
             parsed.port,
             extracted.subdomain,
             extracted.domain,
             extracted.suffix,
             decoded_path,
             decoded_params,
             decoded_query,
             decoded_fragment
             ]
    return parts
def Shannon_entropy(data : str) -> float:
    if not data:
        return 0
    char_count = Counter(data)
    l = len(data)
    s = sum(c*log2(c) for c in char_count.values())
    return log2(l) - s/l
def has_part(parts : list, index : int) -> int:
    if not parts[index]:
        return 0
    return 1
def part_length(parts : list, index : int) -> int:
    return len(parts[index])
def part_entropy(parts : list, index : int) -> float:
    return Shannon_entropy(parts[index])
def digit_ratio(data : str) -> float:
    if not data:
        return 0.0
    return sum(c.isdigit() for c in data) / len(data)
def dot_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '.')
def hyphen_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '-')
def hash_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '#')
def percent_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '%')
def slash_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '/')
def at_sign_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '@')
def ampersand_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '&')
def equal_count(data : str) -> int:
    if not data:
        return 0
    return sum(1 for c in data if c == '=')
def strange_char_count(data : str) -> int:
    if not data:
        return 0
    valid_pattern = r'[^a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]'
    strange_chars = re.findall(valid_pattern, data)
    return len(strange_chars)
def is_ip(data : str) -> int:
    try:
        ipaddress.ip_address(data)
        return 1
    except ValueError:
        return 0
def levenshtein(data : str, file_whitelist : str) -> dict:
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
def part_count(extracted : list) -> int:
    count = 0
    for part in url_structure:
        if extracted[part]:
            count += 1
    return count
def consonant_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    consonants = [c for c in letters if c not in VOWELS]
    return len(consonants) / len(letters)
def has_suspicious_keyword(data : str) -> int:
    if not data:
        return 0
    text_lower = data.lower()
    return 1 if any(kw in text_lower for kw in SUSPICIOUS_KEYWORDS) else 0
def char_repeated_ratio(data : str) -> float:
    if not data or len(data) < 2:
        return 0.0
    repeated = sum(
        1 for i in range(1, len(data))
        if data[i] == data[i-1]
    )
    return repeated / (len(data) - 1)
def max_consecutive_char(data : str) -> int:
    if not data:
        return 0
    max_consecutive = 1
    current_consecutive = 1
    for i in range(1, len(data)):
        if data[i] == data[i-1]:
            current_consecutive += 1
            max_consecutive = max(max_consecutive, current_consecutive)
        else:
            current_consecutive = 1
    return max_consecutive



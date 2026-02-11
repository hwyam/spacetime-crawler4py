import re
import json
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag, parse_qsl
from bs4 import BeautifulSoup

ALLOWED_DOMAINS = ("ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu",)

TRAP_KEYWORDS = ("calendar", "replytocom=", "sort=", "filter=", "session=",)

STOPWORDS = {"a","an","the","and","or","but","if","then","else","for","to","of","in","on","at","by","with","as",
             "is","are","was","were","be","been","being","it","its","this","that","these","those","from","into",
             "we","you","your","i","me","my","our","they","them","their","he","she","his","her","not","no","yes",
             "can","could","would","should","may","might","will","just","do","does","did","done","have","has","had",
             "about","over","under","more","most","some","any","all","each","other","such","than"}

UNIQUE_URLS = set()
SUBDOMAIN_TO_URLS = {}
WORD_FREQ = Counter()
LONGEST_PAGE = {"url": None, "words": 0}

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    if resp is None or resp.status != 200 or resp.raw_response is None:
        return []

    base_url = getattr(resp.raw_response, "url", None) or resp.url or url
    base_url, _ = urldefrag(base_url)

    try:
        ctype = resp.raw_response.headers.get("Content-Type", "").lower()
        if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
            return []
    except Exception:
        pass

    try:
        content = resp.raw_response.content
        if not content:
            return []
    except Exception:
        return []

    soup = BeautifulSoup(content, "html.parser")

    _update_stats(base_url, soup)

    out_links = []
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if not href:
            continue

        abs_url = urljoin(base_url, href)
        abs_url, _ = urldefrag(abs_url)
        out_links.append(abs_url)

    return out_links

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        if not url or not isinstance(url, str):
            return False

        url = url.strip()
        if not url:
            return False

        url, _ = urldefrag(url)
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        if not _allowed_host(host):
            return False

        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            r"|png|tiff?|mid|mp2|mp3|mp4"
            r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx"
            r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            r"|epub|dll|cnf|tgz|sha1"
            r"|thmx|mso|arff|rtf|jar|csv"
            r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower(),
            ):
            return False

        if len(url) > 250:
            return False

        if parsed.query:
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if len(params) >= 8:
                return False

        low = url.lower()
        if any(k in low for k in TRAP_KEYWORDS):
            return False

        parts = [p for p in parsed.path.lower().split("/") if p]
        if len(parts) >= 12:
            return False
        if len(parts) >= 6 and len(set(parts)) <= 2:
            return False

        return True

    except TypeError:
        return False
    
def _allowed_host(host: str) -> bool:
    for d in ALLOWED_DOMAINS:
        if host == d or host.endswith("." + d):
            return True
    return False


def _visible_text(soup: BeautifulSoup) -> str:
    for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "svg"]):
        tag.decompose()
    text = soup.get_text(separator=" ", strip=True)
    return text


def _tokenize(text: str):
    return re.findall(r"[a-zA-Z]+", text.lower())


def _update_stats(page_url: str, soup: BeautifulSoup):
    parsed = urlparse(page_url)
    host = (parsed.hostname or "").lower()
    if not _allowed_host(host):
        return

    if page_url in UNIQUE_URLS:
        return
    UNIQUE_URLS.add(page_url)

    if host not in SUBDOMAIN_TO_URLS:
        SUBDOMAIN_TO_URLS[host] = set()
    SUBDOMAIN_TO_URLS[host].add(page_url)

    text = _visible_text(soup)
    tokens = _tokenize(text)

    wc = len(tokens)
    if wc > LONGEST_PAGE["words"]:
        LONGEST_PAGE["words"] = wc
        LONGEST_PAGE["url"] = page_url

    for w in tokens:
        if len(w) <= 2:
            continue
        if w in STOPWORDS:
            continue
        WORD_FREQ[w] += 1

    if len(UNIQUE_URLS) % 200 == 0:
        _dump_stats()


def _dump_stats(path: str = "crawl_stats.json"):
    subdomain_counts = {k: len(v) for k, v in SUBDOMAIN_TO_URLS.items()}
    data = {
        "unique_pages": len(UNIQUE_URLS),
        "longest_page_url": LONGEST_PAGE["url"],
        "longest_page_words": LONGEST_PAGE["words"],
        "top_50_words": WORD_FREQ.most_common(50),
        "subdomains": dict(sorted(subdomain_counts.items(), key=lambda x: x[0])),
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass
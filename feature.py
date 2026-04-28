import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            self.soup = BeautifulSoup(self.response.text, 'html.parser')  # ✅ Fixed: self.response
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        # ✅ CORRECTED FEATURE EXTRACTION ORDER
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIp - ✅ FIXED
    def UsingIp(self):
        try:
            # Extract domain and check if it's an IP
            domain = self.domain.split(':')[0]  # Remove port if present
            ipaddress.ip_address(domain)
            return 1  # Using IP - Phishing indicator
        except:
            return -1  # Not using IP - Legitimate

    # 2. longUrl - ✅ FIXED (More strict)
    def longUrl(self):
        url_length = len(self.url)
        if url_length < 54:
            return -1  # Short URL - Legitimate
        elif url_length <= 75:
            return 0   # Moderate length - Suspicious
        else:
            return 1   # Long URL - Phishing

    # 3. shortUrl - ✅ FIXED
    def shortUrl(self):
        shorteners = [
            'bit\.ly', 'goo\.gl', 'shorte\.st', 'go2l\.ink', 'x\.co', 'ow\.ly', 't\.co',
            'tinyurl', 'tr\.im', 'is\.gd', 'cli\.gs', 'yfrog\.com', 'migre\.me', 'ff\.im',
            'tiny\.cc', 'url4\.eu', 'twit\.ac', 'su\.pr', 'twurl\.nl', 'snipurl\.com',
            'short\.to', 'BudURL\.com', 'ping\.fm', 'post\.ly', 'Just\.as', 'bkite\.com',
            'snipr\.com', 'fic\.kr', 'loopt\.us', 'doiop\.com', 'short\.ie', 'kl\.am',
            'wp\.me', 'rubyurl\.com', 'om\.ly', 'to\.ly', 'bit\.do', 'lnkd\.in', 'db\.tt',
            'qr\.ae', 'adf\.ly', 'bitly\.com', 'cur\.lv', 'tinyurl\.com', 'ity\.im',
            'q\.gs', 'is\.gd', 'po\.st', 'bc\.vc', 'twitthis\.com', 'u\.to', 'j\.mp',
            'buzurl\.com', 'cutt\.us', 'u\.bb', 'yourls\.org', 'x\.co', 'prettylinkpro\.com',
            'scrnch\.me', 'filoops\.info', 'vzturl\.com', 'qr\.net', '1url\.com', 'tweez\.me',
            'v\.gd', 'tr\.im', 'link\.zip\.net'
        ]
        pattern = '|'.join(shorteners)
        if re.search(pattern, self.url, re.IGNORECASE):
            return 1  # Short URL service - Phishing
        return -1     # No short URL - Legitimate

    # 4. Symbol@ - ✅ FIXED
    def symbol(self):
        if re.findall("@", self.url):
            return 1  # Contains @ symbol - Phishing
        return -1     # No @ symbol - Legitimate

    # 5. Redirecting// - ✅ FIXED
    def redirecting(self):
        if self.url.rfind('//') > 6:
            return 1  # Multiple redirects - Phishing
        return -1     # Normal - Legitimate

    # 6. prefixSuffix - ✅ FIXED
    def prefixSuffix(self):
        try:
            if '-' in self.domain:
                return 1  # Hyphen in domain - Phishing
            return -1     # No hyphen - Legitimate
        except:
            return 0     # Error - Suspicious

    # 7. SubDomains - ✅ FIXED
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count <= 2:
            return -1  # Few subdomains - Legitimate
        elif dot_count == 3:
            return 0   # Moderate - Suspicious
        else:
            return 1   # Many subdomains - Phishing

    # 8. HTTPS - ✅ FIXED
    def Hppts(self):
        try:
            if self.urlparse.scheme == 'https':
                return -1  # HTTPS - Legitimate
            return 1       # HTTP - Phishing
        except:
            return 0       # Error - Suspicious

    # 9. DomainRegLen - ✅ FIXED
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            
            # Handle list dates
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if expiration_date and creation_date:
                # Calculate months difference
                months = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
                if months >= 12:
                    return -1  # Long registration - Legitimate
                return 1       # Short registration - Phishing
            return 0
        except:
            return 0

    # 10. Favicon - ✅ FIXED
    def Favicon(self):
        try:
            if not self.soup:
                return 0
                
            for link in self.soup.find_all('link', rel=True):
                if 'icon' in link.get('rel', []) and link.get('href'):
                    favicon_url = link['href']
                    # Check if favicon is from external domain
                    if self.domain not in favicon_url and not favicon_url.startswith('/'):
                        return 1  # External favicon - Phishing
            return -1  # Local favicon - Legitimate
        except:
            return 0

    # 11. NonStdPort - ✅ FIXED
    def NonStdPort(self):
        try:
            if ':' in self.domain:
                return 1  # Non-standard port - Phishing
            return -1     # Standard port - Legitimate
        except:
            return 0

    # 12. HTTPSDomainURL - ✅ FIXED
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return 1  # HTTPS in domain - Phishing
            return -1     # Normal domain - Legitimate
        except:
            return 0

    # 13. RequestURL - ✅ FIXED
    def RequestURL(self):
        try:
            if not self.soup:
                return 0
                
            total, internal = 0, 0
            
            # Check images
            for img in self.soup.find_all('img', src=True):
                total += 1
                if self.domain in img['src'] or img['src'].startswith('/'):
                    internal += 1
            
            # Check other resources
            tags = ['audio', 'embed', 'iframe', 'source', 'track', 'video']
            for tag in tags:
                for element in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain in element['src'] or element['src'].startswith('/'):
                        internal += 1
            
            if total == 0:
                return 0
                
            percentage = (internal / total) * 100
            if percentage >= 80:
                return -1  # Mostly internal - Legitimate
            elif percentage >= 50:
                return 0   # Mixed - Suspicious
            else:
                return 1   # Mostly external - Phishing
                
        except:
            return 0

    # 14. AnchorURL - ✅ FIXED
    def AnchorURL(self):
        try:
            if not self.soup:
                return 0
                
            total, unsafe = 0, 0
            
            for a in self.soup.find_all('a', href=True):
                total += 1
                href = a['href'].lower()
                if href.startswith('#') or 'javascript:' in href or 'mailto:' in href:
                    unsafe += 1
                elif not (self.domain in href or href.startswith('/')):
                    unsafe += 1
            
            if total == 0:
                return 0
                
            percentage = (unsafe / total) * 100
            if percentage < 20:
                return -1  # Mostly safe - Legitimate
            elif percentage < 60:
                return 0   # Mixed - Suspicious
            else:
                return 1   # Mostly unsafe - Phishing
                
        except:
            return 0

    # 15. LinksInScriptTags - ✅ FIXED
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return 0
                
            total, internal = 0, 0
            
            for link in self.soup.find_all('link', href=True):
                total += 1
                if self.domain in link['href'] or link['href'].startswith('/'):
                    internal += 1
            
            for script in self.soup.find_all('script', src=True):
                total += 1
                if self.domain in script['src'] or script['src'].startswith('/'):
                    internal += 1
            
            if total == 0:
                return 0
                
            percentage = (internal / total) * 100
            if percentage >= 80:
                return -1
            elif percentage >= 50:
                return 0
            else:
                return 1
                
        except:
            return 0

    # 16. ServerFormHandler - ✅ FIXED
    def ServerFormHandler(self):
        try:
            if not self.soup:
                return 0
                
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return -1  # No forms - Legitimate
                
            for form in forms:
                action = form.get('action', '').lower()
                if not action or action == 'about:blank':
                    return 1  # Suspicious action - Phishing
                elif self.domain not in action and not action.startswith('/'):
                    return 0  # External action - Suspicious
                    
            return -1  # All forms seem legitimate
            
        except:
            return 0

    # 17. InfoEmail - ✅ FIXED
    def InfoEmail(self):
        try:
            if not self.response.text:
                return 0
                
            if re.search(r'mailto:|email|contact@|info@', self.response.text, re.IGNORECASE):
                return -1  # Has contact info - Legitimate
            return 1       # No contact info - Phishing
        except:
            return 0

    # 18. AbnormalURL - ✅ FIXED
    def AbnormalURL(self):
        try:
            # Simple check: if domain is in WHOIS data
            if self.whois_response and hasattr(self.whois_response, 'domain_name'):
                return -1  # Normal URL
            return 1       # Abnormal URL
        except:
            return 0

    # 19. WebsiteForwarding - ✅ FIXED
    def WebsiteForwarding(self):
        try:
            redirects = len(self.response.history) if self.response else 0
            if redirects <= 1:
                return -1  # Few redirects - Legitimate
            elif redirects <= 3:
                return 0   # Moderate redirects - Suspicious
            else:
                return 1   # Many redirects - Phishing
        except:
            return 0

    # 20. StatusBarCust - ✅ FIXED
    def StatusBarCust(self):
        try:
            if self.response and re.search(r'onmouseover|status.*bar', self.response.text, re.IGNORECASE):
                return 1  # Custom status bar - Phishing
            return -1     # Normal - Legitimate
        except:
            return 0

    # 21. DisableRightClick - ✅ FIXED
    def DisableRightClick(self):
        try:
            if self.response and re.search(r'event\.button.*==.*2|contextmenu|preventDefault', self.response.text, re.IGNORECASE):
                return 1  # Right click disabled - Phishing
            return -1     # Normal - Legitimate
        except:
            return 0

    # 22. UsingPopupWindow - ✅ FIXED
    def UsingPopupWindow(self):
        try:
            if self.response and re.search(r'alert\(|confirm\(|prompt\(|window\.open', self.response.text, re.IGNORECASE):
                return 1  # Popup windows - Phishing
            return -1     # Normal - Legitimate
        except:
            return 0

    # 23. IframeRedirection - ✅ FIXED
    def IframeRedirection(self):
        try:
            if self.response and re.search(r'<iframe|<frame', self.response.text, re.IGNORECASE):
                return 1  # Iframes detected - Phishing
            return -1     # No iframes - Legitimate
        except:
            return 0

    # 24. AgeofDomain - ✅ FIXED
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                today = datetime.now()
                age_months = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
                if age_months >= 6:
                    return -1  # Old domain - Legitimate
                return 1       # New domain - Phishing
            return 0
        except:
            return 0

    # 25. DNSRecording - ✅ FIXED (Same as AgeofDomain)
    def DNSRecording(self):
        return self.AgeofDomain()  # Same logic

    # 26. WebsiteTraffic - ✅ FIXED (Simplified)
    def WebsiteTraffic(self):
        try:
            # Simplified check - domains with common TLDs are considered legitimate
            legitimate_tlds = ['.com', '.org', '.net', '.edu', '.gov']
            if any(self.domain.endswith(tld) for tld in legitimate_tlds):
                return -1  # Common TLD - Legitimate
            return 1       # Uncommon TLD - Phishing
        except:
            return 0

    # 27. PageRank - ✅ FIXED (Simplified)
    def PageRank(self):
        try:
            # Simple check based on domain characteristics
            if len(self.domain) < 10 and '.' in self.domain:
                return -1  # Short, common domain - Legitimate
            return 1       # Long/uncommon domain - Phishing
        except:
            return 0

    # 28. GoogleIndex - ✅ FIXED
    def GoogleIndex(self):
        try:
            # Simulate Google index check
            common_domains = ['google', 'facebook', 'youtube', 'amazon', 'github', 'stackoverflow']
            if any(domain in self.domain for domain in common_domains):
                return -1  # Well-known domain - Legitimate
            return 1       # Unknown domain - Phishing
        except:
            return 0

    # 29. LinksPointingToPage - ✅ FIXED
    def LinksPointingToPage(self):
        try:
            if self.response:
                link_count = len(re.findall(r'<a\s+href=', self.response.text))
                if link_count > 5:
                    return -1  # Many links - Legitimate
                elif link_count > 0:
                    return 0   # Some links - Suspicious
                else:
                    return 1   # No links - Phishing
            return 0
        except:
            return 0

    # 30. StatsReport - ✅ FIXED
    def StatsReport(self):
        try:
            suspicious_domains = [
                'at\.ua', 'usa\.cc', 'baltazarpresentes', 'pe\.hu', 'esy\.es', 'hol\.es',
                'sweddy\.com', 'myjino\.ru', '96\.lt', 'ow\.ly'
            ]
            pattern = '|'.join(suspicious_domains)
            if re.search(pattern, self.domain, re.IGNORECASE):
                return 1  # Suspicious domain - Phishing
            
            # Check IP reputation (simplified)
            try:
                ip = socket.gethostbyname(self.domain)
                suspicious_ips = [
                    '146\.112\.61\.108', '213\.174\.157\.151', '121\.50\.168\.88'
                ]
                ip_pattern = '|'.join(suspicious_ips)
                if re.search(ip_pattern, ip):
                    return 1  # Suspicious IP - Phishing
            except:
                pass
                
            return -1  # Clean - Legitimate
        except:
            return 0

    def getFeaturesList(self):
        return self.features
from urllib.parse import urlparse
import ipaddress
from api import SafeBrowsingCheck
class URLAnalyzer:
    def __init__(self,url):
        self.score = 0
        self.warnings = []
        self.url = url
    #checking length of url
    def check_length(self):
        if len(self.url)>= 100:
            self.warnings.append("[+]URL Is suspiciously long!")
            self.score += 20
    #checking if url has hostname
    def check_domain(self):
        parsed = urlparse(self.url)
        host = parsed.hostname
        if not host:
            self.warnings.append("[+]URL Has no hostname")
            self.score += 15

    #checking if url is using https protocol
    def check_https(self):
        if not self.url.startswith("https://"):
            self.warnings.append("[+]URL Isn't secured with HTTPS")
            self.score += 30
    #checking if there is suspicious words common in phishing links
    def check_words(self):
        suspicious = [
            "login",
            "password",
            "verify",
            "verification",
            "update",
            "registration",
            "register",
            "pay"
        ]
        for word in suspicious:
            if word.lower() in self.url.lower():
                self.warnings.append(f"[+]Suspicious word \"{word}\" in URL")
                self.score += 5
    #checking if url has ipadress inside
    def check_ipaddress(self):
        parsed = urlparse(self.url)
        host = parsed.hostname
        if not host:
            return    
        try:
            ipaddress.ip_address(host)
            self.warnings.append("[+]URL Uses ip address")
            self.score += 20

        except ValueError:
            pass
    #this function combines all of them with google safe browsing check,
    #  and creating risk level
    def analyze(self):
        self.check_length()
        self.check_domain()
        self.check_https()
        self.check_ipaddress()
        self.check_words()
        api_checker = SafeBrowsingCheck(self.url)
        api_warnings , api_score = api_checker.check()
        self.score += api_score
        self.score = min(self.score,100)
        risk_level = ""
        if 5 <= self.score <=20:
            risk_level = "Low risk"
        if 20 <= self.score <= 50:
            risk_level = "Medium risk"
        if 51 <= self.score <= 70:
            risk_level = "High risk"
        if self.score >= 100:
            risk_level = "Phishing"
        return self.warnings , self.score, api_warnings , risk_level
     
        
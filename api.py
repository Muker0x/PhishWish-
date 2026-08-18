import requests
import os 


class SafeBrowsingCheck:
    def __init__(self,url):
        self.url = url
        self.warnings = []
        self.score = 0

    

    def check_safe_browsing(self):
        api_key = os.getenv("SAFE_BROWSING_API_KEY")
        if not api_key:
            return

        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        data = {
            "client": {"clientId":"PhishWish", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
            "platformTypes":["ANY_PLATFORM"],
            "threatEntryTypes":["URL"],
            "threatEntries":[{"url":self.url}]
            }

        }
        #trying to avoid api failure with try/except 
        try:
            response = requests.post(endpoint,params={"key": api_key},json=data)
            result = response.json()
            matches = result.get("matches")
            if matches:
                self.score += 100
                self.warnings.append("[!]URL is flagged by google safe browsing")
                threat_type = matches[0].get("threatType")
                if threat_type == "SOCIAL_ENGINEERING":
                    self.warnings.append("[+]Social Engineering")
                if threat_type == "MALWARE":
                    self.warnings.append("[+]Malware")
                return threat_type

        except:
            self.warnings.append("[-] Google safe browsing check failed ")


    def check(self):
        self.check_safe_browsing()
        return self.warnings , self.score
        
    

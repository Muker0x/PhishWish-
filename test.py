import unittest
from analyzer import URLAnalyzer
from api import SafeBrowsingCheck
from unittest.mock import patch
import requests
class testing(unittest.TestCase):

    def test_domain(self):
        analyzer = URLAnalyzer("https://example.com")
        analyzer.check_domain()

        self.assertEqual(analyzer.score,0)
        self.assertEqual([],analyzer.warnings)

        analyzer = URLAnalyzer("https://")
        analyzer.check_domain()

        self.assertEqual(analyzer.score,15)
        self.assertIn("[+]URL Has no hostname",analyzer.warnings)
        
        #Catched unwanted behavior 
        # analyzer = URLAnalyzer("https://.../")
        # analyzer.check_domain()

        # self.assertEqual(analyzer.score,15)
        # self.assertIn("[+]URL Has no hostname",analyzer.warnings)


    def test_length(self):
        
        analyzer = URLAnalyzer("https://example.com")
        analyzer.check_length()

        self.assertEqual(analyzer.score,0)
        self.assertEqual([],analyzer.warnings)

        analyzer = URLAnalyzer("https://example.com/aaaaaaaaa@@@@@@@@@@@@@@@############$$$$$$$$$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        analyzer.check_length()

        self.assertEqual(analyzer.score,20)
        self.assertIn("[+]URL Is suspiciously long!",analyzer.warnings)

        analyzer = URLAnalyzer("https://store.com/store/headphones/wireless/apple")
        analyzer.check_length()

        self.assertEqual(analyzer.score,0)
        self.assertEqual([],analyzer.warnings)

    def test_https(self):
        analyzer = URLAnalyzer("https://example.com/")
        analyzer.check_https()

        self.assertEqual(analyzer.score, 0)
        self.assertEqual([],analyzer.warnings)

        analyzer = URLAnalyzer("http://example.com/")
        analyzer.check_https()

        self.assertEqual(analyzer.score, 30)
        self.assertIn("[+]URL Isn't secured with HTTPS",analyzer.warnings)
    def test_words(self):
        analyzer = URLAnalyzer("https://example.com/")
        analyzer.check_words()

        self.assertEqual(analyzer.score, 0)
        self.assertEqual([],analyzer.warnings)

        analyzer = URLAnalyzer("https://example.com/pay/login/update")
        analyzer.check_words()

        self.assertEqual(analyzer.score, 15)
        self.assertEqual(
            [
            "[+]Suspicious word \"login\" in URL", 
            "[+]Suspicious word \"update\" in URL", 
            "[+]Suspicious word \"pay\" in URL"
        ],
        analyzer.warnings)
        
        analyzer = URLAnalyzer("https://examplepay.login/")
        analyzer.check_words()
        
        self.assertEqual(analyzer.score,10)
        self.assertEqual(["[+]Suspicious word \"login\" in URL", 
        "[+]Suspicious word \"pay\" in URL"],
        analyzer.warnings)

        analyzer = URLAnalyzer("https://paypal.com/")
        analyzer.check_words()
        
        self.assertEqual(analyzer.score,5)
        self.assertEqual(["[+]Suspicious word \"pay\" in URL"],analyzer.warnings)


    def test_ipaddress(self):

        analyzer = URLAnalyzer("https://example.com/")
        analyzer.check_ipaddress()
        
        self.assertEqual(analyzer.score,0)
        self.assertEqual([],analyzer.warnings)

        analyzer = URLAnalyzer("https://192.12.64.75/")
        analyzer.check_ipaddress()
        
        self.assertEqual(analyzer.score,20)
        self.assertIn("[+]URL Uses ip address",analyzer.warnings)

        analyzer = URLAnalyzer("https://example.com/192.12.64.75/")
        analyzer.check_ipaddress()
        
        self.assertEqual(analyzer.score,0)
        self.assertEqual([],analyzer.warnings)  


    def test_analyze(self):
        analyzer = URLAnalyzer("https://example.com/")
        warnings, score, api_warnings, risk_level = analyzer.analyze()
        self.assertEqual([],warnings)
        self.assertEqual(score,0)
        self.assertEqual([],api_warnings)
        self.assertEqual("",risk_level)

        analyzer = URLAnalyzer("http://example.com/pay")
        warnings, score, api_warnings, risk_level = analyzer.analyze()
        self.assertEqual(
            [
            "[+]URL Isn't secured with HTTPS",
            "[+]Suspicious word \"pay\" in URL"
        ],
        warnings)
        self.assertEqual(score,35)
        self.assertEqual([],api_warnings)
        self.assertEqual("Medium risk",risk_level)

        analyzer = URLAnalyzer("http://192.64.12.78/register/verification")
        warnings, score, api_warnings, risk_level = analyzer.analyze()
        self.assertEqual(
            [
                
            "[+]URL Isn't secured with HTTPS",
            "[+]URL Uses ip address",
            "[+]Suspicious word \"verification\" in URL", 
            "[+]Suspicious word \"register\" in URL",
            ],
        warnings)

        self.assertEqual(score,60)
        self.assertEqual([],api_warnings)
        self.assertEqual("High risk",risk_level)

        analyzer = URLAnalyzer("http://paypal.com/login/directory/assets/some.random.words///this.is.obviously.phishing./helloworld/")
        warnings, score, api_warnings, risk_level = analyzer.analyze()
        self.assertEqual(
            [
                "[+]URL Is suspiciously long!",
                "[+]URL Isn't secured with HTTPS",
                "[+]Suspicious word \"login\" in URL",
                "[+]Suspicious word \"pay\" in URL",
                
            ],
            warnings

        )
        self.assertEqual(score,60)
        self.assertEqual([],api_warnings)
        self.assertEqual("High risk", risk_level)
    #mocking requests for avoid depending on apis connection
    @patch ("api.requests.post")
    def test_api_malware(self,mock_post):
        mock_post.return_value.json.return_value = {
            "matches": [
                {
                    "threatType":"MALWARE"
                }
            ]
        }

        analyzer = SafeBrowsingCheck("https://fake-malware.com/")
        threat_type = analyzer.check_safe_browsing()
        self.assertEqual(analyzer.score,100)
        self.assertEqual("MALWARE",threat_type)
        self.assertIn("[!]URL is flagged by google safe browsing",analyzer.warnings)
        self.assertIn("[+]Malware", analyzer.warnings)

    @patch ("api.requests.post")
    def test_api_soceng(self,mock_post):
        mock_post.return_value.json.return_value = {
            "matches": [
                {
                    "threatType":"SOCIAL_ENGINEERING"
                }
            ]
        }
        analyzer = SafeBrowsingCheck("https://fake-socengineering.com/")
        threat_type = analyzer.check_safe_browsing()
        self.assertEqual(analyzer.score,100)
        self.assertIn("[!]URL is flagged by google safe browsing",analyzer.warnings)
        self.assertIn("[+]Social Engineering",analyzer.warnings)
        self.assertEqual("SOCIAL_ENGINEERING",threat_type)



    @patch ("api.requests.post")
    def test_api_failure(self,mock_post):
        mock_post.side_effect = requests.RequestException("Connection failed")
        analyzer = SafeBrowsingCheck("https://fake-socengineering.com/")
        threat_type = analyzer.check_safe_browsing()
        self.assertEqual(analyzer.score,0)
        self.assertIn("[-] Google safe browsing check failed ",analyzer.warnings)

    

if __name__ == "__main__":
    unittest.main()
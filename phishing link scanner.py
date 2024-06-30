import requests #makes https requests to web services and APIs
import re  #regular expressions, string matching (TOC)
from urllib.parse import urlparse # breaks URLs into their components
import whois # retrieve WHOIS information abt domain names
import datetime #date and time operations
     
'''using a combined approach of database lookup, heauristic analysis
and WHOIS checks considering that these three are the best options 
from the possibilities'''
 
def check_phishtank(api_key, url):
    print("First Check!")
#request parameters as per Phishtank database found in API page
    params = {
        'format': 'json',
        'app_key': api_key,
        'url': url
    }
#url' : url,
#'format' : 'json',
#'app_key' : api_key
    
#for all formats reg Phishtank check https://phishtank.org/api_info.php
#will check the url and get back
    getback = requests.post("https://checkurl.phishtank.com/checkurl/", params=params)
    if getback.status_code == 200:
        data = getback.json()
#response format for PHP/JSON 
        return data['results']['in_database']and data['results']['phish_id'] and data['results']['phish_detail_page'] and data['results']['verified'] and data['results']['valid']
    else:
        return False
    

#for URL syntax refer https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Syntax
#for length refer https://serpstat.com/blog/how-long-should-be-the-page-url-length-for-seo/

def analyze_url_structure(url):
    print("Second Check!")
    parsed_url = urlparse(url)
    if len(url) > 75: 
        return True

#netloc = network location
    if '@' in parsed_url.netloc or '%' in parsed_url.netloc:
        return True

#checking for multiple subdomains since legitimate sites have one subdoamin only    
    if parsed_url.netloc.count('.') > 2:
        return True
    return False 

#can rather check Phishtank - an extra added method.
def check_suspicious_domain(url):
    print("Third Check!")
    suspicious_domains = ['bit.ly', 'goo.gl', 'tinyurl.com']
    parsed_url = urlparse(url) 
    return any(domain in parsed_url.netloc for domain in suspicious_domains) 



def check_whois(url):
    print("Fourth Check!")
    domain = urlparse(url).netloc
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            print("WHOIS check: Creation date is None")
            return False
        
        age_in_days = (datetime.datetime.now() - creation_date).days
        if age_in_days < 30:
            return True
    except Exception as e:
        print(f"WHOIS check failed for domain {domain}: {e}")
        return True

    return False

def phishing_link_scanner(api_key, url):
    #print("Final Check!")
    if check_phishtank(api_key, url):
        return "Known phishing site"
    if analyze_url_structure(url):
        return "Heuristic detection indicate suspicion"
    if check_suspicious_domain(url):
        return "Suspicious domain detected"
    if check_whois(url):
        return "Failed whois check"
    return "URL is safe"



if __name__=="__main__":
    api_key = 'Phistank_api_key'
    url = input("Enter URL to check: ")
    result = phishing_link_scanner(api_key,url)
    print(result)
    



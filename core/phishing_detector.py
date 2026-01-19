import os
import re
import json
import socket
import ssl
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup
import requests
import tldextract

class PhishingDetector:
    def __init__(self):
        self.database_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database')
        
        # Load databases from files
        self.suspicious_data = self._load_json_database('suspicious_domains.json')
        self.whitelist_data = self._load_json_database('whitelist.json')
        self.known_phishing_data = self._load_json_database('known_phishing.json')
        
        # Initialize from loaded data
        self.suspicious_keywords = self.suspicious_data.get('suspicious_keywords', [])
        self.suspicious_tlds = self.suspicious_data.get('suspicious_tlds', [])
        self.url_shorteners = self.suspicious_data.get('url_shorteners', [])
        
        self.whitelist = self._build_whitelist()
        self.known_phishing_domains = self.known_phishing_data.get('known_phishing_domains', [])
        self.phishing_patterns = self.known_phishing_data.get('phishing_patterns', [])
        
        # Thresholds for scoring
        self.high_risk_threshold = 0.7
        self.medium_risk_threshold = 0.4
        
        # Store details of the last analyzed URL
        self.last_analysis_result = None
    
    def _load_json_database(self, filename):
        """Load JSON database from file"""
        try:
            file_path = os.path.join(self.database_dir, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return json.load(f)
            else:
                print(f"Warning: Database file {filename} not found")
                return {}
        except Exception as e:
            print(f"Error loading database {filename}: {str(e)}")
            return {}
    
    def _build_whitelist(self):
        """Build a comprehensive whitelist from all trusted domains"""
        whitelist = set()
        
        # Add all trusted domains from different categories
        for category in ['trusted_domains', 'trusted_banks', 'trusted_payment_services']:
            whitelist.update(self.whitelist_data.get(category, []))
            
        return whitelist
        
    def analyze_url(self, url, analyze_content=False):
        """Analyze a URL for phishing indicators"""
        if not url or not isinstance(url, str):
            return False
            
        # Parse the URL
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Extract domain parts
        extracted = tldextract.extract(url)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Initialize scoring
        score = 0
        reasons = []
        
        # Check if domain is in known phishing list (immediate high risk)
        if self._is_known_phishing(base_domain):
            self.last_analysis_result = {
                'url': url,
                'threat_score': 95,
                'reasons': [f"Domain {base_domain} matches known phishing indicators"]
            }
            return True
        
        # Check if domain is in whitelist (likely safe)
        if self._is_in_whitelist(base_domain):
            self.last_analysis_result = {
                'url': url,
                'threat_score': 5,
                'reasons': [f"Domain {base_domain} is in whitelist"]
            }
            return False
            
        # Check URL characteristics
        url_score, url_reasons = self._check_url_characteristics(url, domain, base_domain)
        score += url_score
        reasons.extend(url_reasons)
        
        # Check domain characteristics
        domain_score, domain_reasons = self._check_domain_characteristics(base_domain, extracted)
        score += domain_score
        reasons.extend(domain_reasons)
        
        # Analyze page content if requested
        if analyze_content:
            try:
                content_score, content_reasons = self._analyze_page_content(url)
                score += content_score
                reasons.extend(content_reasons)
            except Exception as e:
                reasons.append(f"Could not analyze page content: {str(e)}")
        
        # Normalize score to 0-1 range
        score = min(max(score, 0), 1)
        
        # Save last analysis result for UI/alerts
        self.last_analysis_result = {
            'url': url,
            'threat_score': int(round(score * 100)),
            'reasons': reasons
        }
        
        # Determine risk level and return boolean for phishing detection
        return score >= self.medium_risk_threshold

    def get_last_analysis_result(self):
        """Return structured details from the last analyze_url call."""
        return self.last_analysis_result
    
    def _is_in_whitelist(self, domain):
        """Check if a domain is in the whitelist"""
        return domain in self.whitelist
    
    def _is_known_phishing(self, domain):
        """Check if a domain is in the known phishing database or matches phishing patterns"""
        # Direct match in known phishing domains
        if domain in self.known_phishing_domains:
            return True
            
        # Check for pattern matches with common brand names
        common_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'instagram', 
                        'twitter', 'linkedin', 'netflix', 'ebay', 'chase', 'wellsfargo', 'bankofamerica', 
                        'citibank', 'usbank', 'americanexpress', 'amex', 'discover']
                        
        for brand in common_brands:
            for pattern in self.phishing_patterns:
                pattern_domain = pattern.replace('{brand}', brand)
                if pattern_domain in domain or domain in pattern_domain:
                    return True
                    
        return False
        
    def _check_url_characteristics(self, url, domain, base_domain):
        """Check various URL characteristics for phishing indicators"""
        score = 0
        reasons = []
        
        # Check for IP address instead of domain name
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.25
            reasons.append("URL uses IP address instead of domain name")
        
        # Check for excessive subdomains
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count > 3:
            score += 0.15
            reasons.append(f"Excessive subdomains ({subdomain_count})")
        
        # Check for suspicious keywords in URL
        for keyword in self.suspicious_keywords:
            if keyword in url.lower():
                score += 0.1
                reasons.append(f"URL contains suspicious keyword: {keyword}")
                break
        
        # Check for extremely long URL
        if len(url) > 100:
            score += 0.1
            reasons.append(f"Unusually long URL ({len(url)} characters)")
        
        # Check for URL shorteners
        for shortener in self.url_shorteners:
            if shortener in domain:
                score += 0.2
                reasons.append(f"URL uses shortening service: {shortener}")
                break
                
        # Check for encoded characters
        if '%' in url and any(c in url for c in ['%3A', '%2F', '%40', '%2E']):
            score += 0.15
            reasons.append("URL contains encoded characters")
            
        # Check for HTTPS
        if not url.startswith('https://'):
            score += 0.1
            reasons.append("URL does not use HTTPS")
            
        return score, reasons
    
    def _check_domain_characteristics(self, domain, extracted):
        """Check various domain characteristics for phishing indicators"""
        score = 0
        reasons = []
        
        # Check for suspicious TLDs
        if extracted.suffix in self.suspicious_tlds:
            score += 0.2
            reasons.append(f"Suspicious TLD: {extracted.suffix}")
        
        # Check for typosquatting against popular domains
        typosquat_target = self._is_typosquatting(domain)
        if typosquat_target:
            score += 0.3
            reasons.append(f"Possible typosquatting of {typosquat_target}")
        
        # Check domain age (placeholder - would require WHOIS lookup)
        # This would be implemented with a proper WHOIS lookup service
        # For now, we'll skip this check
        
        # Check for domain with unusual characters
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            score += 0.15
            reasons.append("Domain contains unusual characters")
            
        # Check for numeric domain
        if re.search(r'^\d+', extracted.domain):
            score += 0.1
            reasons.append("Domain starts with numbers")
            
        # Check for hyphens in domain
        if '-' in extracted.domain:
            hyphen_count = extracted.domain.count('-')
            if hyphen_count > 1:
                score += 0.1
                reasons.append(f"Domain contains multiple hyphens ({hyphen_count})")
                
        return score, reasons
    
    def _is_typosquatting(self, domain):
        """Check if a domain is likely typosquatting a popular domain"""
        popular_domains = list(self.whitelist)[:50]  # Use top 50 from whitelist
        
        # Extract the domain without TLD for comparison
        domain_parts = domain.split('.')
        domain_name = '.'.join(domain_parts[:-1]) if len(domain_parts) > 1 else domain
        
        for popular in popular_domains:
            # Extract popular domain without TLD
            popular_parts = popular.split('.')
            popular_name = '.'.join(popular_parts[:-1]) if len(popular_parts) > 1 else popular
            
            # Skip if domains are identical
            if domain_name == popular_name:
                continue
                
            # Check for Levenshtein distance (simplified)
            if self._levenshtein_distance(domain_name, popular_name) <= 2:
                return popular
                
            # Check for character substitution
            if self._has_character_substitution(domain_name, popular_name):
                return popular
                
        return None
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _has_character_substitution(self, s1, s2):
        """Check for common character substitutions (e.g., 0 for o, 1 for l)"""
        substitutions = {
            '0': 'o', 'o': '0',
            '1': 'l', 'l': '1', 'i': '1', '1': 'i',
            '5': 's', 's': '5',
            '3': 'e', 'e': '3',
            'rn': 'm', 'm': 'rn',
            'vv': 'w', 'w': 'vv'
        }
        
        # Try substituting each character and check if strings match
        for i in range(len(s1)):
            if i < len(s1):
                char = s1[i]
                if char in substitutions:
                    s1_mod = s1[:i] + substitutions[char] + s1[i+1:]
                    if s1_mod == s2:
                        return True
                        
        # Try the same for s2
        for i in range(len(s2)):
            if i < len(s2):
                char = s2[i]
                if char in substitutions:
                    s2_mod = s2[:i] + substitutions[char] + s2[i+1:]
                    if s2_mod == s1:
                        return True
                        
        return False
    
    def _analyze_page_content(self, url):
        """Analyze the content of a webpage for phishing indicators"""
        score = 0
        reasons = []
        
        try:
            # Set a timeout to avoid hanging on slow sites
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for login forms
            login_forms = soup.find_all('form')
            password_inputs = soup.find_all('input', {'type': 'password'})
            if login_forms and password_inputs:
                score += 0.2
                reasons.append("Page contains login form with password field")
            
            # Check for security-related terms that might be used to trick users
            security_terms = ['secure', 'security', 'verify', 'confirmation', 'authenticate', 'validate']
            page_text = soup.get_text().lower()
            for term in security_terms:
                if term in page_text:
                    score += 0.05
                    reasons.append(f"Page contains security-related term: {term}")
            
            # Check for favicon (phishing sites often don't have one)
            favicon = soup.find('link', rel=lambda x: x and ('icon' in x or 'shortcut icon' in x))
            if not favicon:
                score += 0.1
                reasons.append("Page does not have a favicon")
            
            # Check for poor HTML quality (often indicative of phishing)
            if len(response.text) < 1000:
                score += 0.1
                reasons.append("Page has unusually small HTML content")
                
            # Check for external resources from different domains
            scripts = soup.find_all('script', src=True)
            links = soup.find_all('link', href=True)
            imgs = soup.find_all('img', src=True)
            
            external_domains = set()
            parsed_url = urllib.parse.urlparse(url)
            base_domain = parsed_url.netloc
            
            for element in scripts + links + imgs:
                src = element.get('src') or element.get('href')
                if src and not src.startswith('data:') and not src.startswith('#'):
                    try:
                        if not src.startswith('http'):
                            # Handle relative URLs
                            if src.startswith('/'):
                                src = f"{parsed_url.scheme}://{base_domain}{src}"
                            else:
                                src = f"{parsed_url.scheme}://{base_domain}/{src}"
                                
                        src_domain = urllib.parse.urlparse(src).netloc
                        if src_domain and src_domain != base_domain:
                            external_domains.add(src_domain)
                    except:
                        pass
                        
            if len(external_domains) > 10:
                score += 0.1
                reasons.append(f"Page loads resources from many external domains ({len(external_domains)})")
                
            # Check for obfuscated JavaScript
            scripts_content = soup.find_all('script')
            for script in scripts_content:
                if script.string and len(script.string) > 100:
                    # Check for typical obfuscation patterns
                    if re.search(r'\\x[0-9a-f]{2}', script.string) or \
                       re.search(r'eval\(', script.string) or \
                       re.search(r'document\.write\(unescape\(', script.string):
                        score += 0.2
                        reasons.append("Page contains potentially obfuscated JavaScript")
                        break
                        
        except Exception as e:
            # If we can't analyze the page, slightly increase the score
            score += 0.05
            reasons.append(f"Could not analyze page content: {str(e)}")
            
        return score, reasons

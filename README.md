## Phishing Link Scanner

### Task 1: Phishing Link Detection
## Phishing Link Scanner

This repository contains a Phishing Link Scanner designed to detect and classify potentially malicious URLs. The scanner employs a combination of heuristic analysis and third-party services to identify phishing threats.

### Features

1. **PhishTank Database Check**: Verifies the URL against the PhishTank database to identify known phishing sites.
2. **URL Structure Analysis**: Analyzes the structure of the URL for common phishing characteristics.
3. **Suspicious Domain Check**: Checks if the URL uses commonly abused URL shortening services.
4. **WHOIS Lookup**: Performs a WHOIS lookup to determine the age of the domain, flagging newly created domains as suspicious.

### Usage

1. **Install dependencies**:
    ```bash
    pip install requests python-whois
    ```
2. **Run the scanner**:
    ```bash
    python phishing_link_scanner.py
    ```

3. **Example**:
    ```python
    api_key = 'YOUR_PHISHTANK_API_KEY'  # Replace with your PhishTank API key
    url = input("Enter the URL to check: ")
    result = phishing_link_scanner(api_key, url)
    print(result)
    ```

---

Additional tasks and features will be detailed below as they are developed.

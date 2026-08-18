# PhishWish-

A Python desktop application that analyzes URLs for phishing indicators.

I built this after learning about phishing attacks during my cybersecurity studies
Wanted a tool that could quickly flag suspicious URLs before clicking them

## What it does

- Checks if URL uses HTTPS
- Detects IP addresses used instead of domain names
- Flags suspicious keywords common in phishing URLs
- Checks URL length
- Validates domain existence
- Integrates with Google Safe Browsing API for real-time threat detection
- Gives a risk score out of 100 with a risk level label

## Project Structure
PhishWish/
├── main.py # entry point
├── analyzer.py # core URL analysis logic
├── api.py # Google Safe Browsing API integration
├── gui.py # Tkinter desktop interface
└── test.py # unit tests with API mocking

## Setup

Install dependencies:
```bash
pip install requests
```

Set your Google Safe Browsing API key:
```bash
export SAFE_BROWSING_API_KEY="your_key_here"
```

Run the app:
```bash
python3 main.py
```

## Running Tests

```bash
python3 test.py
```

## Requirements

- Python 3.x
- requests
- tkinter (built into Python)
- Google Safe Browsing API key (free at console.cloud.google.com)

## Disclaimer

this project is for educational purposes , Always verify suspicious URLs through multiple sources.
## Screenshot 
<img width="1920" height="1080" alt="Screenshot_2026-08-18_00_05_27" src="https://github.com/user-attachments/assets/72c3c3f7-9e92-46ee-933e-613e38d1c29f" />
<img width="1920" height="1080" alt="Screenshot_2026-08-18_00_05_25" src="https://github.com/user-attachments/assets/d28bde5a-d96e-4e86-943d-31ed2b6c8953" />

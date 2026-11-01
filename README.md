# Phishing_URL_Detector
# PhishGuard — URL Security Scanner

An educational cybersecurity project that analyzes URL text for common suspicious indicators and explains the findings in a Flask web interface.

## Features
- URL normalization and parsing
- Checks for IP-address hostnames, HTTP scheme, `@` syntax, punycode, long URLs, many subdomains, unusual ports, URL shorteners, suspicious words, and possible brand impersonation
- Explainable heuristic score and risk summary
- Does not visit submitted URLs
- Simple responsive HTML/CSS interface
- Health endpoint at `/health`

## Requirements
- Python 3.10 or newer
- pip

## Run on Windows
Open Command Prompt or PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser. To check that Flask is responding, visit `http://127.0.0.1:5000/health`.

## Run on Ubuntu/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## Safe test examples
These use reserved example domains and documentation IP addresses; they are not live phishing sites:
- `https://www.google.com`
- `https://google.com.example.org`
- `http://192.0.2.10/login`
- `http://google.com@evil.example/verify`

Do not open suspicious links in a browser just to test the scanner. Paste the URL as text.

## Important limitations
- This is an educational rule-based prototype, not a production security product.
- The score is a heuristic indicator score, **not a probability** and not a verified verdict.
- A URL with indicators is not necessarily malicious; a URL with no indicators is not guaranteed safe.
- The registered-domain function handles common examples but is not a complete Public Suffix List implementation. For broader coverage, use a maintained Public Suffix List-aware library and keep it updated.
- Brand domains are an illustrative configurable list and may become incomplete.
- It does not inspect webpage content, verify TLS certificates, resolve DNS, follow redirects, or query threat-intelligence services.
- The Random Forest model from earlier versions is not included in this starter package because a model trained on only a handful of samples cannot be evaluated as reliable. Add it only after training and evaluating on a representative labeled dataset.
- The Flask development server is intended for local demonstration only. Do not expose it directly to the internet.

## Suggested project presentation
1. Problem statement: phishing links use deceptive URL structures.
2. Objectives: parse URLs, report indicators, provide an explainable assessment.
3. Technologies: Python, Flask, HTML, CSS.
4. Workflow: input → parse → security rules → heuristic score → report.
5. Demonstration: use safe reserved examples and show the actual output.
6. Testing: record expected indicators and actual results; report false positives/false negatives honestly.
7. Limitations and future scope: threat-intelligence integration, robust Public Suffix List parsing, DNS/redirect analysis in a controlled environment, and evaluated ML support.

## Project structure
```text
PhishGuard_Project/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
└── static/
    └── style.css
```

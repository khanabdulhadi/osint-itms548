# OSINT App

A PyQt5-based desktop application for performing common OSINT (Open Source Intelligence) lookups, including IP geolocation, DNS subdomain enumeration, keyword-based news/entity search, and URL scanning.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Reports](#reports)

## Features

- **Geolocation Lookup**: Enter an IP address or hostname to retrieve geolocation data and view it on an interactive Leaflet map.
- **Domain Subdomain Enumeration**: Discover subdomains for a given domain.
- **Keyword Search**: Search for recent articles (via GDELT) and entities (via Wikidata) by keyword.
- **URL Scan**: Fetch scans for a URL, including DNS, ASN, and reverse lookup details.
- **Export Results**: Save lookup results to CSV files for further analysis.


```bash
pip install -r requirements.txt
python main.py
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/khanabdulhadi/osint-dashboard.git
   cd osint-dashboard
   ```
2. **Ensure your virtual environment is active** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # on Windows: venv\Scripts\activate
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the application:

```bash
python main.py
```

- Navigate between tabs to perform lookups.
- Click **Search** to start a lookup; a progress dialog appears until results load.
- Click **Export CSV** in the status bar after running lookups to save all gathered data.

## Project Structure

```
├── gui/
│   └── main_window.py         # PyQt5 GUI implementation
├── data_sources/
│   ├── ip_api.py              # IP geolocation API wrapper
│   ├── subdomains.py          # DNS enumeration module
│   ├── gdelt.py               # GDELT article search wrapper
│   ├── wikidata.py            # Wikidata entity search
│   └── urlscan.py             # urlscan.io scanning module
├── analysis/
│   └── data_aggregator.py     # CSV export logic
├── reports/                   # CSV export output directory
├── main.py                    # Entry point
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## Reports
All CSV exports are saved in the `reports/` directory with timestamped filenames.

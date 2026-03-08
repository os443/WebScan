## WebScan a lightweight reconnaissance tool written in Python.

## Features

- IP & GeoIP lookup
- DNS enumeration (AAAA, MX, NS)
- HTTP header inspection
- Server detection (Nmap with header fallback)
- SSL certificate inspection
- Directory brute-force using dirsearch
- Nmap Scanning

## Requirements

- Python (tested with 3.12)

## Installation

- pip install -r requirements.txt

## Notes

- If the server is behind a CDN or proxy (Cloudflare, etc.), results may be shown as Hidden.
- Dirsearch is a third-party tool by maurosoria and is not authored by this project.
- Nmap is a third-party tool by Gordon Lyon and is not authored by this project.

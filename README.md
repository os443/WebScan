# WebScan is a lightweight reconnaissance and directory brute-force tool written in Python.

## Features

- IP & GeoIP lookup
- DNS enumeration (AAAA, MX, NS)
- HTTP header inspection
- Server detection (Nmap with header fallback)
- SSL certificate inspection
- Directory brute-force using dirsearch

## Requirements

- Python 3.9+
- Python modules:
  pip install requests dnspython colorama python-nmap or pip install -r 

## Usage

python webscan.py

## Notes

- If the server is behind a CDN or proxy (Cloudflare, etc.), results may be shown as Hidden.
- dirsearch is a third-party tool by maurosoria and is not authored by this project.
- Nmap is a third-party tool by Gordon Lyon and is not authored by this project.

## License

MIT License (u can use/sell/modify it freely)

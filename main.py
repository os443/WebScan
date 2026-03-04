import socket
import os
import requests
import dns.resolver
import ssl
import nmap
import subprocess
from urllib.parse import urljoin
from datetime import datetime, timezone
from colorama import Fore, Style, init

init(autoreset=True)

serverFound = False
httpFound = False

def clear():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def menu():
    clear()
    print(f"""
{Fore.CYAN}    +-----------------------
    |
    | {Fore.YELLOW}WebscanV1 | By Osvrn{Fore.CYAN}
    |
    | {Fore.YELLOW}[1]{Fore.CYAN} Reconnaissance
    | {Fore.YELLOW}[2]{Fore.CYAN} Directory Bruteforce (dirsearch)
    {Style.RESET_ALL}
    """)

menu()

option = input("    > Enter option: ")
target = input("    > Enter target Domain: ")

def recon():
    ip = socket.gethostbyname(target)
    geo = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city").json()

    print(f"\n{Fore.WHITE}    --------------------------------\n")
    print(f"{Fore.CYAN}    Ip Information\n")
    print(f"{Fore.WHITE}    Country:{Style.RESET_ALL} {Fore.GREEN}{geo.get('country')}")
    print(f"{Fore.WHITE}    City:{Style.RESET_ALL} {Fore.GREEN}{geo.get('city')}")
    print(f"{Fore.WHITE}    Ip:{Style.RESET_ALL} {Fore.GREEN}{ip}")

    print(f"\n{Fore.WHITE}    --------------------------------\n")
    print(f"{Fore.CYAN}    DNS Information\n")

    recordTypes = ["AAAA", "MX", "NS"] # AA too put we already have that in IP Information

    for record in recordTypes:
        answers = dns.resolver.resolve(target, record)
        results = [f"{record}: {r}" for r in answers]
        dnsFound = True
        for i in range(0, len(results), 2):
            print(f"{Fore.WHITE}    {results[i]}{Style.RESET_ALL}" + (f" | {Fore.GREEN}{results[i+1]}" if i+1 < len(results) else ""))

    if not dnsFound:
        print(f"{Fore.WHITE}    DNS Records:{Style.RESET_ALL} {Fore.GREEN}Hidden")

    print(f"\n{Fore.WHITE}    --------------------------------\n")
    print(f"{Fore.CYAN}    HTTP Information\n")

    response = requests.get(f"http://{target}", timeout=5, allow_redirects=True)

    for header in ["X-Powered-By","Content-Type","Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-XSS-Protection"]:
        val = response.headers.get(header)
        if val:
            httpFound = True
            print(f"{Fore.WHITE}    {header}:{Style.RESET_ALL} {Fore.GREEN}{val}")

    serverFound = False

    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-sV -p 80,443")
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                svc = scanner[host][proto][port]
                if svc.get("product"):
                    serverFound = True
                    info = svc["product"] + (f" {svc['version']}" if svc.get("version") else "")
                    print(f"{Fore.WHITE}    Server Type:{Style.RESET_ALL} {Fore.GREEN}{info}")

    if not serverFound and response.headers.get("Server"):
        serverFound = True
        print(f"{Fore.WHITE}    Server Type:{Style.RESET_ALL} {Fore.GREEN}{response.headers.get('Server')}")

    if not serverFound:
        print(f"{Fore.WHITE}    Server Type:{Style.RESET_ALL} {Fore.GREEN}Hidden")

    if not httpFound:
        print(f"{Fore.WHITE}    HTTP Headers:{Style.RESET_ALL} {Fore.GREEN}Hidden")

    print(f"\n{Fore.WHITE}    --------------------------------\n")
    print(f"{Fore.CYAN}    SSL Information\n")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert["issuer"])
        subject = dict(x[0] for x in cert["subject"])
        validFrom = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        validTo = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        print(f"{Fore.WHITE}    Issuer:{Style.RESET_ALL} {Fore.GREEN}{issuer.get('organizationName','Unknown')}")
        print(f"{Fore.WHITE}    Subject:{Style.RESET_ALL} {Fore.GREEN}{subject.get('commonName','Unknown')}")
        print(f"{Fore.WHITE}    Valid From:{Style.RESET_ALL} {Fore.GREEN}{validFrom}")
        print(f"{Fore.WHITE}    Valid Until:{Style.RESET_ALL} {Fore.GREEN}{validTo}")
        print(f"{Fore.WHITE}    Days Remaining:{Style.RESET_ALL} {Fore.GREEN}{(validTo - datetime.now(timezone.utc)).days}")

        if cert.get("subjectAltName"):
            print(f"\n{Fore.CYAN}    SANs:{Style.RESET_ALL}")
            for e in cert["subjectAltName"]:
                print(f"{Fore.WHITE}      -{Style.RESET_ALL} {Fore.GREEN}{e[1]}")

    except:
        print(f"{Fore.WHITE}    SSL Information:{Style.RESET_ALL} {Fore.GREEN}Hidden")

def bruteforce():
    print("    --------------------------------------------------------------------------------------------")
    print("    NOTE: This tool (dirsearch) is made by maurosoria (https://github.com/maurosoria) and not me")
    print("    --------------------------------------------------------------------------------------------")
    threads = input("    > Enter threads: ")
    subprocess.run(f"cd dirsearch && python dirsearch.py -u {target} -t {threads}", shell=True)
            
if option == "1":
    recon()
elif option == "2":
    bruteforce()
else:
    print(f"{Fore.RED}    Invalid option{Style.RESET_ALL}")
    os._exit(1) 
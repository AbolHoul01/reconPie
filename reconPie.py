import requests
from bs4 import BeautifulSoup
import socket
import re
import csv
from whois import whois
import argparse

def sitemap(url, depth, currentDepth=0, links=None, seen=None):
    if links is None:
        links = []
    if seen is None:
        seen = set()
    if url in seen or currentDepth > depth:
        return links
    seen.add(url)
    try:
        content = requests.get(url)
        content.raise_for_status()
        x = BeautifulSoup(content.content, 'html.parser')
        base_url = url.rstrip('/')
        for link in x.find_all('a'):
            href = link.get("href")
            if href and not href.startswith('#'):
                if href.startswith('/'):
                    href = base_url + href
                elif not href.startswith('http'):
                    href = base_url + '/' + href
                if href not in seen:
                    links.append(href)
                    if currentDepth < depth:
                        sitemap(href, depth, currentDepth + 1, links, seen)
    except requests.exceptions.RequestException as e:
        print(f"Error processing URL: {url}, Error: {e}")
    return links

def subDomain(url):
    domain = url
    result = []
    try:
        ns = dns.resolver.resolve(domain, 'NS')
        with open("subDomainList.txt", "r") as f:
            subDomainList = f.read().strip().split()
        for subDomain in subDomainList:
            try:
                answers = dns.resolver.resolve(subDomain + "." + domain, "A")
                for ip in answers:
                    result.append(f"{subDomain}.{domain} - {ip}")
            except Exception as e:
                result.append(f"Error resolving DNS for {subDomain}.{domain}: {e}")
    except Exception as e:
        result.append(f"Error resolving name servers for {domain}: {e}")
    return result

def status(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else "No title found"
        return response.status_code, title
    except Exception as e:
        print(f"Error getting title for URL: {url}, Error: {e}")
        return None, None

def ip(url):
    try:
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        ipAddress = socket.gethostbyname(domain)
        return f"The IP address of {domain} is {ipAddress}"
    except Exception as e:
        return f"Error resolving IP for {url}: {e}"

def port(url):
    open_ports = []
    try:
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        ip = socket.gethostbyname(domain)
        for port in range(1, 1024):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
                serv.settimeout(1.0)
                result = serv.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        return open_ports
    except Exception as e:
        return f"Error scanning ports for {url}: {e}"

def regex(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
        emails = re.findall(email_pattern, content)
        phones = re.findall(phone_pattern, content)
        return emails, phones
    except requests.exceptions.RequestException as e:
        return [], []

def whoIs(url):
    try:
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]
        result = whois(domain)
        return result
    except Exception as e:
        return f"Error fetching WHOIS for {url}: {e}"

def args():
    parser = argparse.ArgumentParser(description="Process some inputs.")
    parser.add_argument('--number', type=int, help='process a number.')
    parser.add_argument('--text', type=str, help='process some text')
    parser.add_argument('--flag', action='store_true', default=False, help='set a flag')
    parser.add_argument('files', nargs='*', help='process one or more files')
    args = parser.parse_args()
    if args.number is not None:
        return f"Processing number: {args.number}"
    if args.text is not None:
        return f"Processing text: {args.text}"
    if args.flag:
        return "Flag is set"
    if args.files:
        return f"Processing {len(args.files)} file(s): {', '.join(args.files)}"

if __name__ == "__main__":
    url = input("URL: ").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    domain = url.replace("http://", "").replace("https://", "").split('/')[0]

    depth = 2
    sitemap_result = sitemap(url, depth)
    subdomain_result = subDomain(domain)
    status_code, title = status(url)
    ip_result = ip(domain)
    port_result = port(domain)

    emails, phones = regex(url)
    if isinstance(emails, str):  # This means an error occurred
        print(f"Error in regex function: {emails}")
        emails, phones = [], []

    whois_result = whoIs(domain)
    args_result = args()

    data = [
        ["Sitemap", ", ".join(sitemap_result)],
        ["Subdomains", ", ".join(subdomain_result)],
        ["Status Code", status_code],
        ["Title", title],
        ["IP Address", ip_result],
        ["Open Ports", ", ".join(map(str, port_result))],
        ["Emails", ", ".join(emails)],
        ["Phones", ", ".join(phones)],
        ["WHOIS", str(whois_result)],
        ["Arguments", args_result]
    ]

    fileName = "finalOutput.csv"
    with open(fileName, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Type", "Result"])
        for row in data:
            csvwriter.writerow(row)
                                                        ###############################################################
                                                        # bekhater mahdoodiiat sorat internet list                    #
                                                        # subdomain ha ro kahesh dadam                                #
                                                        # tooye site aparat,mykat,yasdl tavanaii neshan               #
                                                        # dadan subdomain vojood dasht vali bekhater filtering        #  
                                                        # dar site youtube ghabel shenasaii nabood(ehtemal midam)     #
                                                        # bekhater vpn natooneste bashe chon rooye sity mesle         #
                                                        # spotify va soundcloud ham test kardam hamin moshkel bood    #
                                                        ###############################################################
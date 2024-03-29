import nmap
import httpx
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

import logging

logger = logging.getLogger("report")

from __init__ import PROTOCOL_FOLDER, MAX_RUCURSION_DEPTH, URL_GUARD


def save_response(target: str, protocol: str, file_name: str, content: str):
    if "/" in file_name:
        file_name = file_name.replace("/", "_")

    file_path = PROTOCOL_FOLDER(target, protocol).joinpath(file_name)
    file_path.write_text(content)


def try_func(func):
    try:
        return func()
    except Exception as e:
        return "N/A"


def nmap_scan(target_ip: str):
    if "://" in target_ip:
        target_ip = target_ip.split("://")[1]
    if "/" in target_ip:
        target_ip = target_ip.split("/")[0]

    logger.info(f"---Running nmap scan target {target_ip}")
    nm = nmap.PortScanner()
    nm.scan(target_ip, "22-443")
    logger.info(f"Scanned {len(nm.all_hosts())} hosts")
    hosts_active_ports = []
    for host in nm.all_hosts():
        logger.info(f"Host: {host} -> {try_func(lambda: nm[host].hostname())}")
        logger.debug(f"\tHostnames : {try_func(lambda: nm[host].hostnames())}")
        logger.debug(f"\tState : {try_func(lambda: nm[host].state())}")
        logger.debug(f"\tUptime : {try_func(lambda: nm[host].uptime())}")
        logger.debug(
            f"\tMAC Address : {try_func(lambda: nm[host]['addresses']['mac'])}"
        )
        logger.debug(
            f"\tVendor : {try_func(lambda: nm[host]['vendor'][nm[host]['addresses']['mac']])}"
        )
        logger.debug(f"\tOS : {try_func(lambda: nm[host]['osmatch'][0]['name'])}")
        logger.debug(
            f"\tOS Accuracy : {try_func(lambda: nm[host]['osmatch'][0]['accuracy'])}"
        )
        logger.debug(
            f"\tOS Classes : {try_func(lambda: nm[host]['osmatch'][0]['osclass'][0]['type'])}"
        )
        logger.debug(
            f"\tOS Family : {try_func(lambda: nm[host]['osmatch'][0]['osclass'][0]['osfamily'])}"
        )
        logger.debug(
            f"\tOS Gen : {try_func(lambda: nm[host]['osmatch'][0]['osclass'][0]['osgen'])}"
        )
        logger.debug(
            f"\tOS Vendor : {try_func(lambda: nm[host]['osmatch'][0]['osclass'][0]['vendor'])}"
        )
        logger.debug(
            f"\tOS CPE : {try_func(lambda: nm[host]['osmatch'][0]['osclass'][0]['cpe'])}"
        )

        active_ports = set()
        for proto in nm[host].all_protocols():
            logger.debug(f"\tProtocol : {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                logger.debug(
                    f"\t\tport : {port}\tstate : {nm[host][proto][port]['state']}"
                )
                active_ports.add((proto, port))

        hosts_active_ports.append((host, active_ports))

    return hosts_active_ports


def httpx_scan(target_ip: str):
    logger.info(f"---Running httpx scan on {target_ip}")

    for protocol in ["http", "https"]:
        url = f"{protocol}://{target_ip}"
        success, content = get_website_content(url)
        if "/" in target_ip:
            filename = "/".join(target_ip.split("/")[1:])
        else:
            filename = target_ip
        save_response(target_ip, protocol, filename, content)

        if not success:
            continue

        logger.info(
            f"Scanning all sub-links with recursion depth {MAX_RUCURSION_DEPTH}"
        )
        links = get_all_website_links(url, content)
        logger.info(f"Found {len(links)} links in total.")
        for link in links:
            success, content = get_website_content(link[0])
            save_response(target_ip, protocol, link[1], content)


def get_website_content(url: str):
    logger.info(f"Scanning {url}")
    try:
        response = httpx.get(url)
        logger.debug(f"\tstatus code: {response.status_code}")
        logger.debug(f"\theaders: {response.headers}")
        logger.debug(f"\tcookies: {response.cookies}")
        return (True, response.text)

    except Exception as e:
        logger.error(f"\tError: {e}")
        return (False, f"[ERROR] {e}")


def is_valid_url(url, base_url):
    """Controlla se l'URL è valido e appartiene allo stesso dominio."""
    parsed_url = urlparse(url)
    for guard in URL_GUARD:
        if guard in parsed_url.path:
            logger.debug(f"Guarded URL: {url}")
            return False
    return bool(parsed_url.netloc) and parsed_url.netloc == urlparse(base_url).netloc


def cached(func):
    cache = {}

    def wrapper(*args):
        if args[0] not in cache:
            cache[args[0]] = func(*args)
        return cache[args[0]]

    return wrapper


@cached
def get_all_website_links(target, response_text, recursion_depth=MAX_RUCURSION_DEPTH):
    """Restituisce tutti i link URL trovati nella `url` fornita."""

    spaces = "  " * (MAX_RUCURSION_DEPTH - recursion_depth)
    logger.info(f"{spaces}Scanning {target}")

    urls = set()
    soup = BeautifulSoup(response_text, "html.parser")
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue

        parsed_href = urlparse(urljoin(target, href))
        composed_href = (
            parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        )
        if not is_valid_url(composed_href, target):
            continue

        urls.add(((composed_href, parsed_href.path)))

    url_lun = len(urls)
    logger.info(f"{spaces}Found {url_lun} links.")
    for url, _ in list(urls):
        if recursion_depth > 0:
            urls |= get_all_website_links(url, httpx.get(url).text, recursion_depth - 1)
    return urls

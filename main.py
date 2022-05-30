#!/usr/bin/python

import sys
import re
import whois
import socket
from os import path
import requests
from yaspin import yaspin

def printUsage():
  print("Usage: ./main.py <domain name>")
  sys.exit(0)

def getFoundUrls(domain):
  file_path = path.relpath("SecLists/Discovery/Web-Content/common.txt")
  urls = []
  with yaspin() as sp:
    sp.color = "yellow"
    with open(file_path) as f:
      for url_path in f:
        sp.text = "Checking common urls: /{0}".format(url_path.strip())
        url = "{0}/{1}".format(domain, url_path)
        r = requests.get(url)
        if r.status_code == 200:
          urls.append(url)
    return urls

def getDatas(domain_name):
  domain = domain_name
  r = requests.get("https://" + domain)
  if r.status_code == 200:
    domain = "https://{0}".format(domain)
  else:
    domain = "https://{0}".format(domain)

  domain_ip = socket.gethostbyname(domain_name)
  domain_infos = whois.query(domain_name)
  domain_aditional_infos = getAdditionalWhoisInfo(domain_name)
  url_founds = getFoundUrls(domain)
  return """
# Informations about {0}

IP: {1}
Registrar: {2}
Registrant: {3}
Country: {4}
Created At: {5}
Expires At: {6}
Last Updated At: {7}

Nameservers:
  * {8}

URLs found:
  * {9}
  """.format(
    domain_name,
    domain_ip,
    domain_infos.registrar,
    domain_infos.registrant,
    domain_infos.registrant_country,
    domain_infos.creation_date,
    domain_infos.expiration_date,
    domain_infos.last_updated,
    domain_infos.last_updated,
    "\n  * ".join( list(domain_infos.name_servers) ),
    "\n  * ".join(url_founds)
  )

if len(sys.argv) != 2:
  printUsage()

domain = sys.argv[1]

if re.search("^http?s://", domain) is None:
  if re.search("^.+\.\w+$", domain) is None:
    printUsage()

domain = re.sub("^https?://", "", domain)

print("Looking for: " + domain)
print("")
print(getDatas(domain))
#!/usr/bin/python3

import re
import requests
import argparse
import base64
import csv
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin

proxies = {}
ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'

indicators = [
    ("V2luZG93cw","VjJsdVpHOTNjdz09",r".W.i.n.d.o.w.s."),
    r"\w{2}\s*=\s*document\.referrer;\s*var\s\w{2}\s*=\s*window\.location\.href;var\s*\w{2}\s*=\s*navigator\.userAgent;",
    r"\w{2}\s*=\s*document\.createElement\W*script\W*\s*\w{2}\.type\s*=\s*\W*[a-zA-Z\/]*\W*\s*\w{2}\.async\s*=\s*(?:true|false);\s*\w{2}\.src\s*=\s*\w{2}"
]

def GetWebsite(url, headers):
    try:
        if "javascript;base64," in url:
            r = base64.b64decode(url.split(",")[1]).decode("UTF-8")
            return r
        if (("https://" in url) | ("http://" in url)):
            r = requests.get(url, headers=headers)
        else:
            if(url.startswith('//')):
                url = url[2:]
            elif(url.startswith('/')):
                url=url[1:]
            try:
                url1 = "https://"+url
                print("trying: "+url1)
                r = requests.get(url1, headers=headers)
            except:
                url2 = "http://"+url
                r = requests.get(url2, headers=headers)
    except:
        print("Cannot connect to {}".format(url))
        r = ""
    return r 

def ParseWebsite(url):
    scripts = []
    r = GetWebsite(url, headers={'User-Agent': ua})
    if(r == ""):
        return scripts
    else:
        soup = BeautifulSoup(r.content, 'html.parser')
        for s in soup.findAll('script'):
            src = s.get('src')
            if src is None:
                scripts.append((url,s.string))
            else:
                src_url = urljoin(url,src)
                src_text = GetWebsite(src_url, headers={'User-Agent': ua})
                try:
                    if type(src_text.content) == bytes:
                        scripts.append((src_url,src_text.content.decode("UTF-8")))
                    else:
                        scripts.append((src_url,str(src_text.content)))
                except:
                    scripts = []
        return scripts

def FindSocGholish(scripts):
    potential_sg = []
    for s in scripts:
        if s == None or s[1] == None:
            continue
        hits = 0
        if "ndsx" in s[1] and "ndsw===undefined" in s[1]:
            hits = hits + 1
        for i in indicators:
            try:
                if s[1] != None:
                    if type(i) is tuple:
                        for regex in i:
                            if re.search(regex,s[1],re.I):
                                hits = hits + 1
                    else:
                        if re.search(i,s[1],re.I):
                            hits = hits + 1
            except:
                print("Error parsing script: {}".format(s[0]))
                print(s[1])
                continue
        if hits > 0:
            potential_sg.append((s,hits))
    return potential_sg

def Stage2Url(script):
    src = re.search(r"\w{2}\.src\s*=\s*\w{2}\(\W*'(.*?)'\W*\)",script[1],re.I)
    url = src.group(1)
    decoded = []
    try:
        decoded.append(base64.b64decode(url).decode("UTF-8"))
        try:
            decoded.append(base64.b64decode(decoded[0]).decode("UTF-8"))
        except:
            pass
    except:
        pass
    decoded.append(url[1::2])
    for d in decoded:
        if ("report" in d) or (d[0] == "/"):
            return d

    return None

def NSDX_Stage2(urls, ref):
    headers = {"Referer": "/".join(ref.split('/')[:3]), "User-Agent" : ua}
    for u in urls:
        url = "http:"+u[1:-1]
        r = requests.get(url, headers=headers, proxies=proxies)
        ip = requests.get("https://ifconfig.co/ip", headers=headers, proxies=proxies)
        if b"ndsx" in r.content:
            print("Trying to extract stage 2 urls...")
            print("")
            if b"new Date().getTime()" in r.content:
                print("___utma cookie setting script detected in response, this is indicator of filtered IP. Try different proxy / VPN")
                print(r.content.decode())
                print("Your IP: {}".format(ip.content.decode()))
                print()
            else:
                print(re.search(r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)", r.content.decode())[0])

def scan(url):
    print("Scanning website {} in progress...".format(url))
    scripts = ParseWebsite(url)
    sg = FindSocGholish(scripts)
    if sg != []:
        stage2 = []
        urls = set()
        for e in sg:
            if "ndsx" in e[0][1]:
                print("Found potential NDSX variant in: {}".format(e[0][0]))
                urls.update(re.findall("'\/\/[^\s]*?'",e[0][1]))
            else:
                print("Found potential SocGholish in {}!".format(e[0][0]))
                print("Potential injection script (matched {:d} out of {:d} indicators):".format(e[1],len(indicators)))
                print(e[0][1])
                print("")
                stage2.append(urljoin(url,Stage2Url(e[0])))
                print("Trying to extract stage 2 urls...")
                print("")
                print("Potential Stage 2 URLs:")
                for u in stage2:
                    if "report" in u:
                        print(u)
                    else:
                        response = GetWebsite(urljoin(url,u),headers={'Host': url.split('/')[2], 'User-Agent': ua, 'referer': url})
                        s2url = Stage2Url(response.content)
                        if s2url is not None:
                            print(s2url)
        if urls != {}:
            NSDX_Stage2(urls, url)                   
    else:
        hit = False
        for script in scripts:
            if re.match(r"[A-Za-z0-9]{32,}", script[0].split("/")[-1]) != None:
                r = GetWebsite(script[0], headers={'User-Agent': ua})
                if r.content == b'':
                    hit = True
                    print("Found potential SocGholish on {}!".format(url))
                    print("Potential injection script (possible false-positive due to a weak indicator): {}".format(script[0]))
                    print("")
        if hit == False:
            print("Couldn't find any SocGholish payload :(")

def main():
    parser = argparse.ArgumentParser(description='SocGholish finder')
    parser.add_argument("-url", type=str, help="URL to check")
    parser.add_argument("-ua", "--user-agent",type=str, help="Specify User-Agent to use with the request")
    parser.add_argument("-f", "--filename", type=str, help="csv of domains to check")
    parser.add_argument("-p", "--proxy", type=str, help="Proxy server to use, supported format: http(s)://user:password@proxy.tld")
    parser.add_argument("-s", "--scripts", action='store_true', help="list all the scripts on the website with their content (useful for debugging or when script doesn't provide correct results)")
    args = parser.parse_args()


    if args.user_agent:
        global ua
        ua = args.user_agent

    if args.proxy:
        global proxies
        proxies = {
            'http' : args.proxy,
            'https' : args.proxy
        }


    if(args.filename):
        print("Scanning file: "+ args.filename)
        with open(args.filename, 'r', encoding='utf-8-sig') as csvFile:
            raw_file = csv.reader(csvFile)
            for row in raw_file:
                url = str(row[0])
                scan(url)

    if( not args.filename and args.url):
        if (args.scripts):
            print(ParseWebsite(args.url))
        else:
            scan(args.url)


    if( (args.filename == None) & (args.url == None)):
        print("Must input a URL or CSV file of domains")
        parser.print_help()
        exit()


if __name__ == "__main__":
    main()

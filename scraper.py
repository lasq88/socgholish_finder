#!/usr/bin/python3

import re
import requests
import argparse
import base64
from bs4 import BeautifulSoup
from urllib.parse import urljoin


indicators = [
    ("V2luZG93cw","VjJsdVpHOTNjdz09",r".W.i.n.d.o.w.s."),
    r"\w{2}\s*=\s*document\.referrer;\s*var\s\w{2}\s*=\s*window\.location\.href;var\s*\w{2}\s*=\s*navigator\.userAgent;",
    r"\w{2}\s*=\s*document\.createElement\W*script\W*\s*\w{2}\.type\s*=\s*\W*[a-zA-Z\/]*\W*\s*\w{2}\.async\s*=\s*(?:true|false);\s*\w{2}\.src\s*=\s*\w{2}"
]

def ParseWebsite(url, ua):
    try:
        r = requests.get(url, headers={'User-Agent': ua})
    except:
        print("Cannot connect to {}".format(url))
    soup = BeautifulSoup(r.content, 'html.parser')
    scripts = []
    for s in soup.findAll('script'):
        src = s.get('src')
        if src is None:
            scripts.append((url,s.string))
        else:
            src_url = urljoin(url,src)
            try:
                src_text = requests.get(src_url, headers={'User-Agent': ua})
            except:
                print("Cannot connect to {}".format(url))
            scripts.append((src_url,src_text.content))
    return scripts

def FindSocGholish(scripts):
    potential_sg = []
    for s in scripts:
        type
        hits = 0
        for i in indicators:
            if type(i) is tuple:
                for regex in i:
                    if re.search(regex,str(s),re.I):
                        hits = hits + 1
            else:
                if re.search(i,str(s),re.I):
                    hits = hits + 1
        if hits > 0:
            potential_sg.append((s,hits))
    return potential_sg

def Stage2Url(script):
    src = re.search(r"\w{2}\.src\s*=\s*\w{2}\(\W*'(.*?)\W*'\)",str(script),re.I)
    url = src.group(1)
    decoded = []
    try:
        decoded.append(str(base64.b64decode(url)))
        try:
            decoded.append(str(base64.b64decode(decoded[0])))
        except:
            pass
    except:
        pass
    decoded.append(url[1::2])
    for d in decoded:
        if "report" in d:
            return d
        elif d[0] == "/":
            return d

    return None



def main():
    parser = argparse.ArgumentParser(description='SocGholish finder')
    parser.add_argument("url", type=str, help="URL to check")
    parser.add_argument("-ua", "--user-agent",type=str, help="Specify User-Agent to use with the request")
    args = parser.parse_args()

    if args.user_agent is None:
        ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36'
    else:
        ua = args.user_agent

    scripts = ParseWebsite(args.url, ua)
    sg = FindSocGholish(scripts)
    if sg != []:
        for e in sg:
            print("Found potential SocGholish on {}!".format(args.url))
            print("Potential injection script (matched {:d} out of {:d} indicators):".format(e[1],len(indicators)))
            print(e[0])
            print("")
            print("Trying to extract stage 2 url...")
            print("")
            print("Potential Stage 2 URLs:")
            print(urljoin(args.url,Stage2Url(e[0])))

if __name__ == "__main__":
    main()

#!/usr/bin/python3
import re
import requests
import argparse
import base64
import csv
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# TODO: Precompile REGEX
# TODO: Find more indicators
# TODO: Remove headers as a flag, we can just randomize in the script if that matters
# TODO: Decode the %2 variant of the SocGholish script
# TODO: Multi-threading on GetWebsite for CSV

# REGEX Indicators for the currently found SocGholish js
indicators = [
    ("V2luZG93cw","VjJsdVpHOTNjdz09",r".W.i.n.d.o.w.s."),
    r"\w{2}\s*=\s*document\.referrer;\s*var\s\w{2}\s*=\s*window\.location\.href;var\s*\w{2}\s*=\s*navigator\.userAgent;",
    r"\w{2}\s*=\s*document\.createElement\W*script\W*\s*\w{2}\.type\s*=\s*\W*[a-zA-Z\/]*\W*\s*\w{2}\.async\s*=\s*(?:true|false);\s*\w{2}\.src\s*=\s*\w{2}"
]

def GetWebsite(url, headers):
    try: # If the URL already starts w/ http(s) the request will just work
        if (("https://" in url) | ("http://" in url)):
            r = requests.get(url, headers=headers)
        else: # else do some string editing
            if(url.startswith('//')):
                url = url[2:]
            elif(url.startswith('/')):
                url=url[1:]
            try:
                url1 = "https://"+url
                print("trying: "+url1)
                r = requests.get(url1, headers=headers)
            except:
                print("trying http://"+url)
                url2 = "http://"+url
                r = requests.get(url2, headers=headers)
    except: # Connection failed. This could be because of a variety of issues - maybe more verbose error messages are needed here
        print("Cannot connect to {}".format(url))
        r = ""
    return r 

def ParseWebsite(url, ua):
    scripts = []
    r = GetWebsite(url, headers={'User-Agent': ua})
    if(r == ""): # if the GetWebsite failed to connect, we can just skip this function
        return scripts
    else: # else we need to parse
        soup = BeautifulSoup(r.content, 'html.parser')
        for s in soup.findAll('script'): # find strings that contain 'script' - may yield FPs!
            src = s.get('src')
            if src is None: # identify .js files directly in the home folder (most samples found here)
                scripts.append((url,s.string))
            else:  # else run this again with the scripts in other folders
                src_url = urljoin(url,src)
                src_text = GetWebsite(src_url, headers={'User-Agent': ua})
                try: # ?? Not sure the point of this bit
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
        hits = 0
        for i in indicators:
            if type(i) is tuple:
                for regex in i:
                    if re.search(regex,s[1],re.I): # This is a little computationally heavy - if we precompile the Rex we can save some effort
                        hits = hits + 1
            else:
                if re.search(i,s[1],re.I):
                    hits = hits + 1
        if hits > 0:
            potential_sg.append((s,hits))
    return potential_sg

def Stage2Url(script): # Only works for the known base64 SocGholish script
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

def scan(url,ua):
    print("Scanning website {} in progress...".format(url))
    scripts = ParseWebsite(url, ua)
    sg = FindSocGholish(scripts)
    if sg != []:
        stage2 = []
        for e in sg:
            print("Found potential SocGholish on {}!".format(e[0][0]))
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
    else:
        print("Couldn't find any SocGholish payload :(")

def main():
    parser = argparse.ArgumentParser(description='SocGholish finder')
    parser.add_argument("-url", type=str, help="URL to check")
    parser.add_argument("-ua", "--user-agent",type=str, help="Specify User-Agent to use with the request")
    parser.add_argument("-f", "--filename", type=str, help="csv of domains to check")
    args = parser.parse_args()

    if (args.user_agent):
        ua = args.user_agent
    else:
        ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36'

    if(args.filename): 
        print("Scanning file: "+ args.filename)
        with open(args.filename, 'r') as csvFile:
            raw_file = csv.reader(csvFile)
            for row in raw_file:
                url = str(row[0])
                scan(url,ua)

    if( not args.filename and args.url):
        print("Scanning url " + args.url)
        scan(args.url,ua)


    if( (args.filename == "") & (args.url == "")):
        print("Must input a URL or CSV file of domains")
        exit()


if __name__ == "__main__":
    main()

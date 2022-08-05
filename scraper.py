#!/usr/bin/python3

import re
import requests
import argparse
from bs4 import BeautifulSoup


def main():
    r = requests.get('https://clutchpoints.com/nba/', headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36'})

    print(r.status_code)

    soup = BeautifulSoup(r.content, 'html.parser')

    for s in soup.findAll('script'):
        src = s.get('src')
        if (src is not None):
            print(src)


if __name__ == "__main__":
    main()

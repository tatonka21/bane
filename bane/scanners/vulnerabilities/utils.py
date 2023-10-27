import subprocess, os, xtelnet, sys, cgi, re, json,platform
from colorama import Fore, Back, Style
from bane.utils.proxer import load_and_parse_proxies_all,get_requests_proxies_from_parameters
from bane.utils.handle_files import read_file,write_file,delete_file,clear_file,create_file

if platform.system()=='Java':
        Fore.WHITE = ""
        Fore.GREEN = ""
        Fore.RED = ""
        Fore.YELLOW = ""
        Fore.BLUE = ""
        Fore.MAGENTA = ""
        Style.RESET_ALL = ""

if sys.version_info < (3, 0):
    if (sys.platform.lower() == "win32") or (sys.platform.lower() == "win64"):
        Fore.WHITE = ""
        Fore.GREEN = ""
        Fore.RED = ""
        Fore.YELLOW = ""
        Fore.BLUE = ""
        Fore.MAGENTA = ""
        Style.RESET_ALL = ""
    import urllib, HTMLParser
    from urlparse import urlparse
    from urllib import unquote as url_decode
else:
    from urllib.parse import urlparse
    from urllib.parse import unquote as url_decode
    import urllib.parse as urllib
    import html.parser as HTMLParser

unicode = str
import requests, socket, random, time, ssl
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import bs4,socks
from bs4 import BeautifulSoup
from bane.common.payloads import *
from bane.utils.pager import *
from bane.utils.js_fuck import js_fuck
from bane.utils.handle_files import write_file, delete_file
from bane.gather_info.info_s import *
from bane.gather_info.ips import *


def crawl(
    u,
    timeout=10,
    html_comments=False,
    user_agent=None,
    bypass=False,
    proxy=None,
    cookie=None,
    headers={}
):
    """
    this function is used to crawl any given link and returns a list of all available links on that webpage with ability to bypass anti-crawlers

    the function takes those arguments:

    u: the targeted link
    timeout: (set by default to 10) timeout flag for the request
    bypass: (set by default to False) option to bypass anti-crawlers by simply adding "#" to the end of the link :)

    usage:

    >>>import bane
    >>>url='http://www.example.com'
    >>>bane.crawl(url)

    >>>bane.crawl(url,bypass=True)"""
    if urlparse(u).path == "":
        u += "/"
    if u.split("?")[0][-1] != "/" and "." not in u.split("?")[0].rsplit("/", 1)[-1]:
        u = u.replace("?", "/?")
    if user_agent:
        us = user_agent
    else:
        us = random.choice(Common_Variables.user_agents_list)
    h = {}
    if bypass == True:
        u += "#"
    if cookie:
        hea = {"User-Agent": us, "Cookie": cookie}
    else:
        hea = {"User-Agent": us}
    hea.update(headers)
    try:
        c = requests.Session().get(
            u, headers=hea, proxies=proxy, timeout=timeout, verify=False
        ).text
        if html_comments == False:
            c = remove_html_comments(c)
        soup = BeautifulSoup(c, "html.parser")
        ur = u.replace(u.split("/")[-1], "")
        """if ur[-1]=='/':
   ur=ur[:-1]"""
        index_link = 0
        h.update(
            {
                -1: (
                    "Source_url",
                    u,
                    urlparse(u).path,
                    [(x, furl.furl(u).args[x]) for x in furl.furl(u).args],
                )
            }
        )
        for a in soup.find_all("a"):
            u = ur
            if a.has_attr("href"):
                try:
                    txt = a.text
                    a = str(a["href"])
                    if "://" not in a:
                        if a[0] == "/":
                            a = a[1 : len(a)]
                        a = u + a
                    if (a not in h.values()) and (u in a):
                        if (a != u + "/") and (a != u):
                            h.update(
                                {
                                    index_link: (
                                        txt,
                                        a,
                                        urlparse(a).path,
                                        [
                                            (x, furl.furl(a).args[x])
                                            for x in furl.furl(a).args
                                        ],
                                    )
                                }
                            )
                            index_link += 1
                except Exception as e:
                    pass
    except Exception as ex:
        pass
    return h

def random_string(size):
    s = ""
    for x in range(size):
        s += random.choice(Common_Variables.source_string)
    return s


def setup_to_submit(form):
    d = {}
    f = {}
    for x in form["inputs"]:
        if x["type"] == "file":
            f.update({x["name"]: x["value"]})
        else:
            d.update({x["name"]: x["value"]})
    return d, f


def setup_proxy(proxies):
    return random.choice(proxies)



def setup_ua(usra):
    if usra:
        return usra
    return random.choice(Common_Variables.user_agents_list)


def valid_parameter(parm):
    try:
        float(parm)
        return False
    except:
        return True

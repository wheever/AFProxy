#!/usr/bin/env python3
# -*- coding: utf-8 -*-

_name = "AFProxy"
__name = "Another Filtering Proxy"
__author__ = 'phoenix'
__version__ = 'v0.4'

CONFIG = "config.ini"
CA_CERTS = "cacert.pem"

import os
import sys
import time
import importlib
import configparser
import fnmatch
import re
import logging
import threading
import ssl
import urllib3
#https://urllib3.readthedocs.org/en/latest/security.html#insecurerequestwarning
urllib3.disable_warnings()

from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from ProxyTool import ProxyRequestHandler, get_cert
from Exceptions import *

from colorama import init, Fore, Back, Style
init(autoreset=True)

# Add CWD to py2exe build's module search path
sys.path.insert(0, '')

class LoadConfig:
    def __init__(self, configfile):
        self.config = configparser.ConfigParser(allow_no_value=True,
                                                inline_comment_prefixes=('#',))
        self.config.read(configfile)
        self.Port = int(self.config['GENERAL'].get('Port'))
        self.URLFilter = self.config['GENERAL'].getboolean('URLFilter')
        self.HeaderFilter = self.config['GENERAL'].getboolean('HeaderFilter')
        self.PageFilter = self.config['GENERAL'].getboolean('PageFilter')
        self.DefaultProxy = self.config['GENERAL'].get('DefaultProxy')
        self.LogLevel = self.config['GENERAL'].get('LogLevel')
        self.ListDir = self.config['GENERAL'].get('ListDir')
        self.ListFiles = {'MatchList': list(self.config['MatchList'].keys()),
                          'PrivoxyList': list(self.config['PrivoxyList'].keys()),
                          'ReplaceList': list(self.config['ReplaceList'].keys())}

class ConnectionPools:
    """
    self.pools is a list of {'proxy': 'http://127.0.0.1:8080',
                             'pool': urllib3.ProxyManager() object,
                             'patterns': ['ab.com', 'bc.net', ...]}
    self.getpool() is a method that returns pool based on host matching
    """
    # Windows default CA certificates are incomplete 
    # See: http://bugs.python.org/issue20916
    # cacert.pem sources:
    # - http://curl.haxx.se/docs/caextract.html
    # - http://certifi.io/en/latest/

    # ssl_version="TLSv1" to specific version
    sslparams = dict(cert_reqs="REQUIRED", ca_certs=CA_CERTS)
    # IE: http://support2.microsoft.com/kb/181050/en-us
    # Firefox about:config
    # network.http.connection-timeout 90
    # network.http.response.timeout 300
    timeout = urllib3.util.timeout.Timeout(connect=90.0, read=300.0)

    def __init__(self, config):
        self.file = config
        self.file_timestamp = os.path.getmtime(config)
        self.loadConfig()

    def loadConfig(self):
        # self.conf has to be inited each time for reloading
        self.conf = configparser.ConfigParser(allow_no_value=True, delimiters=('=',),
                                              inline_comment_prefixes=('#',))
        self.conf.read(self.file)
        self.pools = []
        proxy_sections = [section for section in self.conf.sections()
                          if section.startswith('PROXY')]
        for section in proxy_sections:
            proxy = section.split()[1]
            self.pools.append(dict(proxy=proxy,
                                   # maxsize is the max. number of connections to the same server
                                   pool=[urllib3.ProxyManager(proxy, 10, maxsize=8, timeout=self.timeout, **self.sslparams),
                                         urllib3.ProxyManager(proxy, 10, maxsize=8, timeout=self.timeout)],
                                   patterns=list(self.conf[section].keys())))
        default_proxy = self.conf['GENERAL'].get('DefaultProxy')
        default_pool = ([urllib3.ProxyManager(default_proxy, 10, maxsize=8, timeout=self.timeout, **self.sslparams),
                         urllib3.ProxyManager(default_proxy, 10, maxsize=8, timeout=self.timeout)]
                        if default_proxy else
                        [urllib3.PoolManager(10, maxsize=8, timeout=self.timeout, **self.sslparams),
                         urllib3.PoolManager(10, maxsize=8, timeout=self.timeout)])
        self.pools.append({'proxy': default_proxy, 'pool': default_pool, 'patterns': '*'})

        self.noverifylist = list(self.conf['SSL No-Verify'].keys())
        self.sslpasslist = list(self.conf['SSL Pass-Thru'].keys())

    def reload(self):
        "Called by an external timer periodically"
        mtime = os.path.getmtime(self.file)
        if mtime > self.file_timestamp:
            self.file_timestamp = mtime
            self.loadConfig()
            logger.info(Fore.RED + Style.BRIGHT
                         + "*" * 20 + " CONFIG RELOADED " + "*" * 20)

    def getpool(self, host, httpmode=False):
        noverify = True if httpmode or any((fnmatch.fnmatch(host, pattern) for pattern in self.noverifylist)) else False
        for pool in self.pools:
            if any((fnmatch.fnmatch(host, pattern) for pattern in pool['patterns'])):
                return pool['proxy'], pool['pool'][noverify], noverify

class Timer:
    "Given a list of objects, call their reload() method periodically"

    # The interval seconds between each check
    interval = 1
    signal = True

    def __init__(self):
        self.watch_list = []

    def add(self, obj):
        if obj not in self.watch_list:
            self.watch_list.append(obj)

    def start(self):
        while self.signal:
            time.sleep(self.interval)
            for obj in self.watch_list:
                try:
                    obj.reload()
                except Exception as e:
                    print(e)
                    print('Something Wrong, go ahead anyway...')

    def stop(self):
        self.signal = False

class ModuleReloader:
    def __init__(self, module):
        self.module = module
        self.file = module.__file__
        self.file_timestamp = os.path.getmtime(self.file)

    def reload(self):
        "Called by an external timer periodically"
        mtime = os.path.getmtime(self.file)
        if mtime > self.file_timestamp:
            self.file_timestamp = mtime
            logger.info(Fore.RED + Style.BRIGHT
                         + "*" * 20 + "RELOADING %s" % self.module.__name__ + "*" * 20)
            importlib.reload(self.module)
            initFilters(self.module)

class ProxyServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    pass

class RequestHandler(ProxyRequestHandler):
    server_version = "%s/%s" % (_name, __version__)

    def do_CONNECT(self):
        "Descrypt https request and dispatch to http handler"
        # request line: CONNECT www.example.com:443 HTTP/1.1
        self.host, self.port = self.path.split(":")
        self.proxy, self.pool, self.noverify = pools.getpool(self.host)
        if any((fnmatch.fnmatch(self.host, pattern) for pattern in pools.sslpasslist)):
            # SSL Pass-Thru
            if self.proxy and self.proxy.startswith('https'):
                self.forward_to_https_proxy()
            elif self.proxy and self.proxy.startswith('socks5'):
                self.forward_to_socks5_proxy()
            else:
                self.tunnel_traffic()
            # Upstream server or proxy of the tunnel is closed explictly, so we close the local connection too
            self.close_connection = 1
        else:
            # SSL MITM
            self.wfile.write(("HTTP/1.1 200 Connection established\r\n" +
                              "Proxy-agent: %s\r\n" % self.version_string() +
                              "\r\n").encode('ascii'))
            commonname = '.' + self.host.partition('.')[-1] if self.host.count('.') >= 2 else self.host
            dummycert = get_cert(commonname)
            # set a flag for do_METHOD
            self.ssltunnel = True

            ssl_sock = ssl.wrap_socket(self.connection, keyfile=dummycert, certfile=dummycert, server_side=True)
            # Ref: Lib/socketserver.py#StreamRequestHandler.setup()
            self.connection = ssl_sock
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            # dispatch to do_METHOD()
            self.handle_one_request()

    def do_METHOD(self):
        ""
        if self.ssltunnel:
            # https request
            host = self.host if self.port == '443' else "%s:%s" % (self.host, self.port)
            self.url = "https://%s%s" % (host, self.path)
        else:
            # http request
            self.host = urlparse(self.path).hostname
            host = urlparse(self.path).netloc
            self.proxy, self.pool, self.noverify = pools.getpool(self.host, httpmode=True)
            self.url = self.path
        self.filter = True
        prefix = '[P]' if self.proxy else '[D]'

        ########## Apply URLFilter ##########
        if config.URLFilter:
            if self.applyFilters('URLFilter') == 'GetOut':
                return

        data_length = self.headers.get("Content-Length")
        self.postdata = self.rfile.read(int(data_length)) if data_length else None
        # Remove hop-by-hop headers
        self.purge_headers(self.headers)
        # pool.urlopen() expects a dict like headers container for http request
        headers = urllib3._collections.HTTPHeaderDict()
        [headers.add(key, value) for (key, value) in self.headers.items()]

        ########## Apply HeaderFilterOut ##########
        if config.HeaderFilter:
            if self.applyFilters('HeaderFilter', 'Out') == 'GetOut':
                return

        r = None
        try:
            # Sometimes 302 redirect would fail with "BadStatusLine" exception, and IE11 doesn't restart the request.
            # retries=1 instead of retries=False fixes it.
            r = self.pool.urlopen(self.command, self.url, body=self.postdata, headers=headers,
                                  retries=1, redirect=False, preload_content=False, decode_content=False)
            color = Fore.RED if self.noverify and self.url.startswith('https') else Fore.GREEN
            logger.info(color + '%s "%s %s" %s %s',
                        prefix, self.command, self.url, r.status, r.getheader('Content-Length', '-'))

            self.send_response_only(r.status, r.reason)
            # HTTPResponse.getheader() combines multiple same name headers into one
            # https://login.yahoo.com would fail to login
            # Use HTTPResponse.msg instead
            r.headers = r._original_response.msg

            self.response = r
            ########## Apply HeaderFilterIn ##########
            if config.HeaderFilter:
                if self.applyFilters('HeaderFilter', 'In') == 'GetOut':
                    return

            if self.command == 'HEAD' or r.status in (100, 101, 204, 304):
                self.write_headers(r.headers)
                written = None

            elif r.headers['Content-Type'] in ('text/html', 'text/css') and self.filter == True:

                self.data = r.read(decode_content=True)
                ########## Apply PageFilter ##########
                if config.PageFilter:
                    if self.applyFilters('PageFilter') == 'GetOut':
                        return

                del r.headers['Content-Encoding']
                del r.headers['Content-Length']
                del r.headers['Transfer-Encoding']
                r.headers['Content-Length'] = len(self.data)
                self.write_headers(r.headers)
                self.wfile.write(self.data)

            else:
                self.write_headers(r.headers)
                written = self.stream_to_client(r)
                if "Content-Length" not in r.headers and 'Transfer-Encoding' not in r.headers:
                    self.close_connection = 1

        except urllib3.exceptions.SSLError as e:
            self.sendout_error(self.url, 417, message="SSL Certificate Failed", explain=e)
            logger.error(Fore.RED + Style.BRIGHT + "[SSL Certificate Error] " + self.url)
        except urllib3.exceptions.TimeoutError as e:
            self.sendout_error(self.url, 504, message="Timeout", explain=e)
            logger.warning(Fore.YELLOW + '%s on "%s %s"', e, self.command, self.url)
        except (urllib3.exceptions.HTTPError,) as e:
            self.sendout_error(self.url, 502, message="HTTPError", explain=e)
            logger.warning(Fore.YELLOW + '%s on "%s %s"', e, self.command, self.url)
        finally:
            if r:
                # Release the connection back into the pool
                r.release_conn()

    def applyFilters(self, module_name, direction=False):
        try:
            for flt in sys.modules[module_name].filters:
                if not direction:
                    flt.action(self)
                else:
                    if getattr(flt, direction) == True:
                        flt.action(self)
        except (RequestBlocked, RequestRedirected):
            return 'GetOut'
        except (RequestBypassed, ):
            return 'GoAhead'

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_METHOD

"""
#Information#

* Python default ciphers: http://bugs.python.org/issue20995
* SSL Cipher Suite Details of Your Browser: https://cc.dcsec.uni-hannover.de/
* https://wiki.mozilla.org/Security/Server_Side_TLS
"""
def classCollector(module):
    "parse a module file to collect all top level classes" 
    pattern = re.compile(r"class\s+([^:\s(]+)")
    with open(module.__file__, encoding='utf-8') as f:
        class_list = [pattern.match(line).group(1) for line in f if line.startswith('class')]
    return class_list

def initFilters(module):
    "put selected top level classes from a module into its [filters] list"
    filters = [getattr(module, cls) for cls in classCollector(module)]
    filters = [flt for flt in filters if hasattr(flt, 'action')]
    module.filters = []
    for flt in filters:
        if (getattr(flt, 'active', False) == True) or (
            not hasattr(flt, 'active') and (flt.In or flt.Out)):
            module.filters.append(flt)
            flt.init()

try:
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW('%s %s' % (_name, __version__))

    config = LoadConfig(CONFIG)

    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, config.LogLevel, logging.INFO))
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(message)s', datefmt='[%H:%M:%S]')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    pools = ConnectionPools(CONFIG)

    watcher = Timer()
    watcher.add(pools)

    server = ProxyServer(('', config.Port), RequestHandler)
    for worker in (server.serve_forever, watcher.start):
          thread = threading.Thread(target=worker)
          thread.dameon = True
          thread.start()

    print("=" * 76)
    print('%s %s (urllib3/%s)' % (__name, __version__, urllib3.__version__))
    print()
    print('  Listening    : localhost:%s' % config.Port)
    print('  ParentServer : %s' % config.DefaultProxy)
    print('  URLFilter    : %s' % 'On' if config.URLFilter else 'Off')
    print('  HeaderFilter : %s' % 'On' if config.HeaderFilter else 'Off')
    print('  PageFilter   : %s' % 'On' if config.PageFilter else 'Off')
    print("=" * 76)

    import ListFile
    ListFile.init(config.ListDir, config.ListFiles)
    from ListFile import ListFiles
    for file in ListFiles.values():
        watcher.add(file)

    for module_name in ('URLFilter', 'HeaderFilter', 'PageFilter'):
        if getattr(config, module_name):
            module = importlib.import_module(module_name)
            initFilters(module)
            watcher.add(ModuleReloader(module))

    print("=" * 76)
    
except KeyboardInterrupt:
    print("Quitting...")

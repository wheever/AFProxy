#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
from urllib.parse import urlparse, urlunparse, quote
from Exceptions import *
from ListFile import parse_line_to_regex, ListFiles

from colorama import init, Fore, Back, Style
init(autoreset=True)

logger = logging.getLogger('__main__')

# Class method action() will be passed with the http request object,
# with below attributes:
#
# .url
# .
class HeaderFilter:
    In = False
    Out = False
    urls = ('*',)

    @classmethod
    def init(cls):
        pass

    @classmethod
    def urlMatched(cls, url):
        for filter_url in cls.urls:
            if re.match(parse_line_to_regex(filter_url),
                        url.split('//', maxsplit=1)[1]):
                return True

    @classmethod
    def action(cls, req):
        if cls.urlMatched(req.url):
            cls.do_action(req)

class IEURLFix(HeaderFilter):
    """
    Windows IE encodes the query part of the URL to bytes using the
    "Language for non-Unicde programs' setting, without adding "%"
    in front of each byte.
    The result looks like "?query=\xB4\xBA\xBD\xDA",
    but it should be like "?query=%B4%BA%BD%DA".

    Firefox does it right.

    It would cause problems with Python, because:
    http.server: requestline = str(self.raw_requestline, 'iso-8859-1')
    http.client: self._output(request.encode('ascii'))

    Sometimes the bytes which could be decoded by 'iso-8859-1' can't be
    encoded back by 'ascii', so it would raise UnicodeEncodeError exception.

    Below code use urllib.parse.quote() to escape special characters
    to fix the gotcha.

    Ref: http://www.ruanyifeng.com/blog/2010/02/url_encoding.html
    """
    name = "Fix IE URL Encoding Gotcha"
    In = False
    Out = True
    urls = ('notyet.com',)

    @classmethod
    def init(cls):
        import locale
        cls.encoding = locale.getpreferredencoding(False)

    @classmethod
    def do_action(cls, req):
        if (req.headers['User-Agent']
            and 'Windows' in req.headers['User-Agent']
            and 'Trident' in req.headers['User-Agent']):
            url = urlparse(req.url)
            try:
                url.query.encode('ascii')
            except UnicodeEncodeError:
                # Convert it back to bytes
                query = url.query.encode('iso-8859-1')
                # Convert it back to str
                # https://docs.python.org/3/howto/unicode.html
                # on Windows, Python uses the name “mbcs” to refer to whatever
                # the currently configured encoding is, but it not always works
                query = query.decode(cls.encoding)
                # Escape special characters properly
                query = quote(query, safe='/=%&')
                req.url = urlunparse(list(url[:4]) + [query, ''])
                logger.info(Fore.YELLOW + 'IE URL Gotcha Fiexed.')

class PrintReferer(HeaderFilter):
    "Print Referrer if it differs from the request domain"
    name = "Print Referrer"
    In = False
    Out = True

    @classmethod
    def do_action(cls, req):
        domain = re.match(r"(?:.*?\.)?([^.]+\.[^.]+)$", req.host).group(1)
        referer = req.headers['referer']
        if referer:
            referer_host = referer.split('//')[1].split('/', maxsplit=1)[0]
            if not referer_host.endswith(domain):
                logger.info('Referer: %s', referer)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
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
class PageFilter:
    "Basic web page filter class"
    active = False
    # Default matching all urls
    urls = ('*',)
    string_subs = ()
    regex_subs = ()

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
            page = req.data
            for pattern, repl in cls.string_subs:
                page = page.replace(pattern, repl)
            for pattern, repl in cls.regex_subs:
                page = re.sub(pattern, repl, page)
            req.data = page
            logger.info('PageFilter: [%s]' % cls.name)

class NoIframeJS(PageFilter):
    name = "Remove All JS and Iframe"
    active = True
    urls = ('.badsite.org',
           'andyou.net/.*\.jpe?g',
           'gotyou.com/viewer\.php.*\.jpe?g')
    regex_subs = ((br'(?si)<(script|iframe)\s+.*?</\1>', br'<!-- \1 removed by FILTER: no-js-iframe -->'),
                  )

class ImgDinoFix(PageFilter):
    name = "imgdino.com img fix"
    active = True
    urls = ('imgdino.com/viewer\.php.*\.jpg',
           'imgtiger.com/viewer\.php.*\.jpg')
    string_subs = ((b'-250px 0 0 285px', b''),)

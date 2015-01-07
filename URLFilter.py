#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import logging
from Exceptions import *
from ListFile import ListFiles

from colorama import init, Fore, Back, Style
init(autoreset=True)

logger = logging.getLogger('__main__')

# Class method action() will be passed with the http request object,
# with below attributes:
#
# .url
# .
class URLFilter:
    active = False
    @classmethod
    def init(cls):
        pass

    @classmethod
    def action(cls, req):
        for file in cls.files:
            cls.do_action(req, ListFiles[file.lower()])

class Redirect(URLFilter):
    "Matched URL will be redirected"
    files = ["Redirect.txt"]
    active = True

    @classmethod
    def do_action(cls, req, List):
        url = req.url
        pattern_list, valid_lines = List.patterns
        for pattern in pattern_list:
            match = re.match(pattern, url)
            if match:
                line_number = int(match.lastgroup[1:])
                pattern, repl = valid_lines[line_number]
                new_url = re.sub(pattern, repl, url)
                req.redirect(new_url)
                logger.info(Fore.CYAN + '[%s:%s] %s -> %s', List.filename, line_number, url, new_url)
                raise RequestRedirected()

class Block(URLFilter):
    "Matched URL will be blocked"
    files = ["Block.txt"]
    active = True

    @classmethod
    def do_action(cls, req, List):
        url = req.url.split('//', maxsplit=1)[1]
        if List.match(url):
            req.deny_request()
            raise RequestBlocked()

class PrivoxyBlock(Block):
    "Parse Privoxy action files for blocking URL"
    files = ['user.action', 'default.action']
    active = True

class Bypass(URLFilter):
    "Matched URL will be bypassed from filtering"
    files = ["Bypass.txt"]
    active = True

    @classmethod
    def do_action(cls, req, List):
        url = req.url.split('//', maxsplit=1)[1]
        if List.match(url):
            req.filter = False
            raise RequestBypassed()

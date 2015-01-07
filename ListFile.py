#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# As to Python v3.4.2, number of named groups is limited to 100 max
# See: http://bugs.python.org/issue22437
GROUP_LIMIT = 100

import os
import fnmatch
import re
import logging
from Exceptions import *

from colorama import init, Fore, Back, Style
init(autoreset=True)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

main_logger = logging.getLogger('__main__')

def parse_line_to_regex(line):
    "Parse Privoxy style line to regex pattern"
    # split the line into host and path
    if '/' not in line:
        host = line
        path = ''
    else:
        host, path = line.split('/', maxsplit=1)
    # parse the host from wildcards to regex
    if host.startswith('.') or host.endswith('.'):
        host_list = [host[1:], '*' + host] if host.startswith('.') else [host] *2
        if host_list[0].endswith('.'):
            host_list = [host[:-1] for host in host_list] + [host + '*' for host in host_list]
        # [:-7] to remove the trailing '\Z(?ms)'
        host_regex = '|'.join([fnmatch.translate(host)[:-7] for host in host_list])
    else:
        host_regex = fnmatch.translate('*')[:-7] if host == '' else fnmatch.translate(host)[:-7]
    # replace '.*' with '[^/]*' so the host regex won't match the path string
    host_regex = re.sub(r"(?<!\\)\.\*", "[^/]*", host_regex)
    # parse the path
    path = '.*' if path == '' else path
    # combine the url
    url = host_regex + '/' + path
    return url
    
def compile_regex_list(regex_list, limit=GROUP_LIMIT):
    limit -= 1
    regex_list = regex_list[:]
    compiled = []
    while regex_list:
        temp = regex_list[:limit]
        del regex_list[:limit]
        # It increases the groups number if the patterns in regex_list contain (...)
        # Reduce the temp_list to half size if above situation triggers
        try:
            compiled += [re.compile('|'.join(temp))]
            logger.debug('Compile %d regex.', len(temp))
        except AssertionError as e:
            if str(e).endswith('%d named groups' % GROUP_LIMIT):
                regex_list = temp + regex_list
                limit = limit // 2
                continue
            else:
                raise e
    return compiled

class MatchList:
    """
    Class Methods:

    - init()             Parse the list file to provide below attributes
      * file_timestamp
      * lines            A dict indexed by the line number
      * patterns         Compiled patterns
      * excludes         Compiled excluding patterns

    - isMatched()        Test if a string matches
    """
    def __init__(self, list_dir, filename):
        self.filename = filename
        self.file = os.path.join(list_dir, filename)
        self.file_timestamp = os.path.getmtime(self.file)
        self.parse_file()
        
    def parse_file(self):
        "Combine every line of the file into a single compiled regex pattern"
        pattern_list = []
        exclude_list = []
        bad_lines = 0
        with open(self.file, encoding='utf-8') as f:
            line_number = 0
            for line in f:
                line_number += 1
                orig_line, line = line, line.strip()
                if line.startswith('#') or line == '':
                    continue
                else:
                    excluding = True if line.startswith('~') else False
                    line = line[1:] if excluding else line
                    url = parse_line_to_regex(line)
                    pattern = "(?P<_%s>%s)" % (line_number, url)
                    try:
                        re.compile(pattern)
                        if excluding:
                            exclude_list += [pattern]
                        else:
                            pattern_list += [pattern]
                    except re.error as e:
                        bad_lines += 1
                        logger.info("[%s:%s] %s " + Fore.RED + "%s",
                                    self.filename, line_number, orig_line, e.args)
        self.patterns = compile_regex_list(pattern_list) if pattern_list else []
        self.excludes = compile_regex_list(exclude_list) if exclude_list else []
        logger.info(Fore.GREEN + "[%s] Total: %s - Include: %s - Exclude: %s - Bad: %s",
                    self.filename, line_number, len(pattern_list), len(exclude_list), bad_lines)

    def match(self, url, do_test=re.match):
        """
        Call do_test(pattern, url)
        url is converted to lower case and doesn't include http:// or https://
        """
        for return_value, regex_list in ((False, self.excludes),
                                         (True, self.patterns)):
            for pattern in regex_list:
                match = do_test(pattern, url.lower())
                if match:
                    color = Fore.YELLOW if return_value else Fore.CYAN
                    main_logger.info(color + '[%s:%s] %s', self.filename, match.lastgroup[1:], url)
                    return return_value
            
    def reload(self):
        "Called by an external timer periodically"
        mtime = os.path.getmtime(self.file)
        if mtime > self.file_timestamp:
            self.file_timestamp = mtime
            main_logger.info(Fore.RED + Style.BRIGHT
                             + "*" * 20 + " RELOADING %s " % self.filename + "*" * 20)
            self.parse_file()

class PrivoxyList(MatchList):

    def parse_file(self):
        pattern_list = []
        exclude_list = []
        bad_lines = 0
        status = 0
        block_pattern = re.compile(r'\{\s*\+block')
        unblock_pattern = re.compile(r'\{\s*-block')
        with open(self.file, encoding='utf-8') as f:
            line_number = 0
            for line in f:
                line_number += 1
                orig_line, line = line, line.strip()
                if line.startswith('#') or line == '':
                    continue
                elif block_pattern.match(line):
                    status = 1
                elif unblock_pattern.match(line):
                    status = 2
                elif line.startswith('{'):
                    status = 0
                else:
                    if status > 0:
                        url = parse_line_to_regex(line)
                        pattern = "(?P<_%s>%s)" % (line_number, url)
                        try:
                            re.compile(pattern)
                            if status == 2:
                                exclude_list += [pattern]
                            else:
                                pattern_list += [pattern]
                        except re.error as e:
                            bad_lines += 1
                            logger.info("[%s:%s] %s " + Fore.RED + "%s",
                                        self.filename, line_number, orig_line, e.args)
        self.patterns = compile_regex_list(pattern_list) if pattern_list else []
        self.excludes = compile_regex_list(exclude_list) if exclude_list else []
        logger.info(Fore.GREEN + "[%s] Total: %s - Include: %s - Exclude: %s - Bad: %s",
                    self.filename, line_number, len(pattern_list), len(exclude_list), bad_lines)

class ReplaceList(MatchList):
    """
    Each line of the ReplaceList should be like this:
    <pattern>    <repl>

    Given string will be tested against the pattern and be replaced if matched
    > re.sub(pattern, repl, string)
    """

    def parse_file(self):
        pattern_list = []
        valid_lines = {}
        bad_lines = 0
        with open(self.file, encoding='utf-8') as f:
            line_number = 0
            for line in f:
                line_number += 1
                line = line.strip().split()
                if line == [] or line[0].startswith('#'):
                    continue
                else:
                    if len(line) == 1:
                        bad_lines += 1
                        logger.info("[%s:%s] %s " + Fore.RED + "No Replace Pattern", self.filename, line_number, line[0])
                    else:
                        patt, repl = line
                        if not patt.startswith('http'):
                            bad_lines += 1
                            logger.info("[%s:%s] %s "+ Fore.RED + "Should Start with http", self.filename, line_number, patt)
                        else:
                            pattern = "(?P<_%s>%s)" % (line_number, patt)
                            try:
                                re.compile(pattern)
                                pattern_list += [pattern]
                                valid_lines[line_number] = line
                            except re.error as e:
                                bad_lines += 1
                                logger.info("[%s:%s] %s " + Fore.RED + "%s", self.filename, line_number, patt, e.args)
        self.patterns = (compile_regex_list(pattern_list), valid_lines) if pattern_list else ([], {})
        logger.info(Fore.GREEN + "[%s] Total: %s - Include: %s - Bad: %s",
                    self.filename, line_number, len(pattern_list), bad_lines)

def init(list_dir, list_files):
    for filename in list_files['MatchList']:
        ListFiles[filename] = MatchList(list_dir, filename)
    for filename in list_files['PrivoxyList']:
        ListFiles[filename] = PrivoxyList(list_dir, filename)
    for filename in list_files['ReplaceList']:
        ListFiles[filename] = ReplaceList(list_dir, filename)

ListFiles = {}

if __name__ == "__main__":
    list_dir = 'Lists'
    list_files = {'MatchList': ['Block.txt', 'Bypass.txt'],
                  'PrivoxyList': ['default.action', 'user.action'],
                  'ReplaceList': ['Redirect.txt']}
    init(list_dir, list_files)

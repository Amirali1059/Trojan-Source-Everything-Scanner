#!/usr/bin/env python
# coding: utf-8

# loading libraris
import os
import string
from collections import Counter
from time import time

print(
    """
    ***Trojan-Source-Everything-Scanner***
    
    a new type of attack found which source code is encoded to appears different to a compiler and to the human eye,
    This script check all source codes in all drives for this attack...
"""
)

# Settings
scan_extentions = [
    ".py", ".pyw", ".ipynb", # python
    ".cpp", ".c", ".hpp", ".h", ".o", # c/c++
    ".axd", ".asx", ".asmx", ".ashx", ".aspx", ".asp", # asp .net
    ".java", ".jsp", ".jspx", # java
    ".php" , ".php4", ".php3", # php
    ".htm", ".jhtml", ".shtml", ".rhtml", ".xhtml", ".html", ".xml", ".rss", ".svg" # html/xml
    ".js", ".cs", ".css", # js/css
    ".pl", ".rb", # ruby/perl/other
    ]
malware_chars = [
    '\u202A',
    '\u202B',
    '\u202D',
    '\u202E',
    '\u2066',
    '\u2067',
    '\u2068',
    '\u202C',
    '\u2069',
]

# list all drives
available_drives = [
    '%s:' % d for d in string.ascii_uppercase if os.path.exists('%s:' % d)]

# Discover all drives
scan_ext = tuple(scan_extentions)
malware_files = []
all_files = []
for drive in available_drives:
    print(f"Discovering drive {drive} ...", end=" ")
    for root, dirs, files in os.walk(drive+"\\"):
        print("|/-\\"[(int(time() % 1*4))], end="\b")
        all_files += [root+"\\"+file for file in files if file.lower().endswith(scan_ext)]
    print("Done!")

print(f"found {len(all_files)} scanable files ...")

# scan all drives
print(f"Scannig all founded files ...", end=" ")
for file in all_files:
    print("|/-\\"[(int(time() % 1*4))], end="\b")
    try:
        raw_code = open(file, "r", encoding="utf-8").read()
    except (UnicodeDecodeError, FileNotFoundError, PermissionError):
        continue
    for char in malware_chars:
        if char in raw_code:
            count = raw_code.count(char)
            chrs = "char" if count == 1 else "chars"
            malware_files.append(f"found {count} \\u{ord(char):x} {chrs} in \"{file}\"!")
print("Done!")
print("\nScan Results:\n")
print("\n".join(malware_files))
print()
os.system("pause")

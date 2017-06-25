#!/usr/bin/python3

import csv, sys

maximum = 0

with open(sys.argv[1], newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile, quoting=csv.QUOTE_NONNUMERIC)
    for row in reader:
        maximum += row[1]

with open(sys.argv[1], newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile, quoting=csv.QUOTE_NONNUMERIC)
    for row in reader:
        print("{:d},{:0.20f}".format(int(row[0]), row[1] / maximum))

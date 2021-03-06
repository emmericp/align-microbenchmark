#!/usr/bin/python3

import csv, sys

data = []

with open(sys.argv[1], newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile, quoting=csv.QUOTE_MINIMAL)
    first = next(reader)
    if first[0].startswith('#'):
        data.append(first)
        first = next(reader)
    reference = float(first[1])
    data.append([first[0], 0])
    for row in reader:
        data.append([row[0], 100. * float(row[1])/reference - 100])

with open(sys.argv[1].split(".")[0] + "_formated.csv", 'w', newline='') as f:
    writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
    writer.writerows(data)

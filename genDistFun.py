#!/usr/bin/python3

import csv, sys

with open(sys.argv[1], newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile, quoting=csv.QUOTE_NONNUMERIC)
    csum = 0
    print("local myCDF = {")
    for row in reader:
        csum += row[1]
        print("\t[{:d}] = {:0.20f},".format(int(row[0]), csum))

    print("}")

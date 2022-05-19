#!/usr/bin/python3.8

N = 2 * int(1e6) + 1000

with open("input.txt", "w") as output_file:
    for i in range(N):
        output_file.write(str(i % 2))
    output_file.write("\n")

#!/usr/bin/python3

import random
import sys

def gen_expr(depth: int) -> str:
	opnd = '+' if random.randint(0, 1) <= 0 else '-'

	return ''.join([gen_term(depth), opnd, gen_term(depth + 1)])

def gen_term(depth: int):
	opnd = '*'

	return ''.join([gen_factor(depth), opnd, gen_factor(depth + 1)])

def gen_factor(depth: int):
	if depth >= MAX_DEPTH:
		return str(random.randint(1, 10))
	return '(' + gen_expr(depth + 1) + ')'


SIZES = list(i for i in range(int(1e5), 1 + 2 * int(1e6), int(1e5)))

d_max = 10
for size in SIZES:
	print(f"Generating expr for {size=}")
	for d in range(d_max, 0, -1):
		MAX_DEPTH = d
		expr = gen_expr(0)
		if len(expr) <= size:
			if d == d_max:
				d_max += 1
			break
	
	print(f"Init length: {len(expr)}")
	diff = size - len(expr)
	expr += (diff // 2 + 1) * "+1"

	print(f"Expression length: {len(expr)}")
	with open(f"{size}_expr.txt", "w") as f:
		f.write(expr)

#include <iostream>
#include <fstream>
#include <cstring>

const int N = 1000000;
const char *filename = "/janus_project/comet_evaluator/expr_input/1000000_expr.txt";

const int MAX_N = 2 * (1e6) + 1000;
const int MOD = 10007;

char s[MAX_N];

int expr_len, ptr;

int compute_expr();

int compute_factor()
{
	int factor = 0;
	if (s[ptr] == '(') {
		++ptr;
		factor = compute_expr();
		++ptr;
	}
	else {
		while (ptr < N && s[ptr] >= '0' && s[ptr] <= '9') {
			factor = factor * 10 + s[ptr++] - '0';
		}
	}
	
	return factor % MOD;
}

int compute_term()
{
	int f1 = compute_factor();
	++ptr;
	int f2 = compute_factor();

	return (f1 * f2) % MOD;
}

int compute_expr()
{
	int t1 = compute_term();
	int op = s[ptr++] == '+' ? 1 : -1;
	int t2 = compute_term();

	int res = (t1 + op * t2);
	while (res < 0) {
		res += MOD;
	}
	res %= MOD;

	return res;
}

int main()
{
	std::ifstream f;
	f.open(filename);
	std::cout << "Reading from " << filename << std::endl;

	char c;
	f.read(s, MAX_N);
	expr_len = strlen(s);

	std::cout << "Length of expression is: " << expr_len << std::endl;

	std::cout << "Result of expression is (MODULO " << MOD << "): " << compute_expr() << std::endl;

	return 0;
}

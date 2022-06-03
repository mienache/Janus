#include <iostream>

const int N = int(1e6);

bool is_pow10(int n)
{
	if (n < 1) {
		return 0;
	}

	while (n % 10 == 0) {
		n /= 10;
	}

	return (n == 1);
}

int main()
{
	std::cout << "Approximating PI using Leibniz formula and N = " << N << std::endl;

	double pi = 0;
	for (int i = 1; i <= N; ++i) {
		int sign = -1;
		if (i % 2) {
			sign = 1;
		}

		pi += sign * ((double) 1 / (2 * i - 1));

		if (is_pow10(i)) {
			std::cout << "At iteration " << i << " PI ~= " << pi * 4.0 << std::endl;
		}
	}

	pi *= 4.0;

	std::cout << "Final PI ~= " << pi << std::endl;

	return 0;
}

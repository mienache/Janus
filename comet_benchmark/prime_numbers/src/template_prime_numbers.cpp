#include <iostream>

using namespace std;

const int N = int(1e6);

bool is_prime[N + 1];
bool is_prime_brute[N + 1];

void eratoshenes()
{
	for (int i = 2; i <= N; ++i) {
		is_prime[i] = 1;
	}

	for (int i = 2; i <= N; ++i) {
		if (!is_prime[i]) {
			continue;
		}
		for (int j = i + i; j <= N; j += i) {
			is_prime[j] = 0;
		}
	}

	int num_primes = 0;
	for (int i = 2; i <= N; ++i) {
		num_primes += is_prime[i];
	}
	
	std::cout << "Primes found by Eratosthenes: " << num_primes << std::endl;
}

void brute_force() {
	for (int i = 2; i <= N; ++i) {
		is_prime_brute[i] = 1;
	}

	for (int i = 3; i <= N; ++i) {
		for (int j = 2; j * j <= i; ++j) {
			if (i % j == 0) {
				is_prime_brute[i] = 0;
				break;
			}
		}
	}

	int num_primes = 0;
	for (int i = 2; i <= N; ++i) {
		num_primes += is_prime_brute[i];
	}

	std::cout << "Primes found by brute-force: " << num_primes << std::endl;
}

int main()
{
	std::cout << "Computing prime numbers until N = " << N << std::endl;
	eratoshenes();
	brute_force();
	return 0;
}

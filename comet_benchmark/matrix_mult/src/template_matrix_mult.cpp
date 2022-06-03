#include <iostream>

const int N = int(1e3);


int MOD = 10007;
int A[N][N], B[N][N], C[N][N];

void generateMatrix(int (*Mat)[N], int seed) {
	for (int i = 0; i < N; ++i) {
		for (int j = 0; j < N; ++j) {
			int val = seed;
			for (int k = 0; k <= 1 + (i * j + seed) % 100; ++k) {
				val += k;
				val %= MOD;
			}
			Mat[i][j] = val;
		}
	}
}

void multMatrices()
{
	for (int i = 0; i < N; ++i) {
		for (int j = 0; j < N; ++j) {
			for (int k = 0; k < N; ++k) {
				C[i][j] += A[i][k] * B[k][j];
				C[i][j] %= MOD;
			}
		}
	}
}

int main()
{
	std::cout << "Multiplying matrices of sizes N = " << N << std::endl;

	generateMatrix(A, 7);
	generateMatrix(B, 9);
	
	int sum = 0;
	for (int i = 0; i < N; ++i) {
		for (int j = 0; j < N; ++j) {
			sum += A[i][j];
			sum %= MOD;
		}
	}

	std::cout << "Sum of all elements of result = " << sum << std::endl;
	
	return 0;
}



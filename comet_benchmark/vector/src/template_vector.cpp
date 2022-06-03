#include <iostream>
#include <vector>

using namespace std;

const int N = int(1e6);
vector <int> v;

int main()
{
	v.reserve(N);
	std::cout << "Generating vector of N = " << N << " elements " << std::endl;
	for (int i = 1; i <= N; ++i) {
		v.push_back(i);
	}

	int64_t sum = 0;
	for (int i = 0; i < v.size(); ++i) {
		sum += v[i];
	}

	std::cout << "Sum of vector = " << sum << std::endl;	

	return 0;
}

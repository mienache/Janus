#include <iostream>
#include <algorithm>

using namespace std;

const int N = 1000000;
const int MOD = 100057;


void merge_sort(int *v, int *tmp, int n)
{
	if (n == 1) {
		return;
	}

	const int n1 = n  / 2 + n % 2;
	const int n2 = n - n1;
	merge_sort(v, tmp, n1);
	merge_sort(v + n1, tmp, n2);
	
	int *left_ptr = v;
	int *right_ptr = v + n1;
	int *left_lim = v + n1;
	int *right_lim = v + n;

	int index = 0;
	while(1) {
		if (*left_ptr < *right_ptr) {
			tmp[index] = *left_ptr;
			left_ptr++;
		}
		else {
			tmp[index] = *right_ptr;
			right_ptr++;
		}

		index++;
		
		if (left_ptr == left_lim) {
			break;
		}
		
		if (right_ptr == right_lim) {
			break;
		}
	}

	while (left_ptr < left_lim) {
		tmp[index] = *left_ptr;
		index++;
		left_ptr++;
	}

	while (right_ptr < right_lim) {
		tmp[index] = *right_ptr;
		index++;
		right_ptr++;
	}

	for (int i = 0; i < n; ++i) {
		v[i] = tmp[i];
	}
}


int array[N], tmp[N], validator[N];
void do_merge_sort()
{
	cout << "Sorting N = " << N << " elements with merge sort" << endl;

	array[0] = 7;
	validator[0] = 7;
	for (int i = 1; i < N; ++i) {
		array[i] = (1LL * array[i - 1] * 1432437) % MOD;
		validator[i] = array[i];
	}

	const int to_show = 3;

	cout << "Showing first and last " << to_show << " elements. " << endl;
	cout << "Before sorting: " << endl;
	for (int i = 0; i < to_show; ++i) {
		cout << i << ": " << array[i] << endl;
	}

	cout << "..." << endl;
	for (int i = N - to_show; i < N; ++i) {
		cout << i << ": " << array[i] << endl;
	}

	merge_sort(array, tmp, N);

	sort(validator, validator + N);
	
	bool is_ok = 1;
	for (int i = 0; i < N; ++i) {
		if (array[i] != validator[i]) {
			std::cout << i << ": " << array[i] << " != " << validator[i] << std::endl;
			is_ok = 0;
			break;
		}
	}

	cout << "Showing first and last " << to_show << " elements. " << endl;
	cout << "After sorting: " << endl;
	for (int i = 0; i < to_show; ++i) {
		cout << i << ": " << array[i] << endl;
		cout << i << ": " << validator[i] << endl;
	}

	cout << "..." << endl;
	for (int i = N - to_show; i < N; ++i) {
		cout << i << ": " << array[i] << endl;
		cout << i << ": " << validator[i] << endl;
	}

	cout << "IS SORTING OK: " << is_ok << endl;
}

		
int main()
{
	do_merge_sort();

	return 0;
}


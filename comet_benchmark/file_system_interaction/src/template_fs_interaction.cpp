#include <iostream>
#include <fstream>

const int N = int(1e6);

char s[N + 1];

int main()
{
	std::ifstream f("/janus_project/comet_evaluator/fs_interaction_files/input.txt");
	std::ofstream g("/janus_project/comet_evaluator/fs_interaction_files/output.txt", std::ios_base::app);

	std::cout << "Reading N = " << N << " characters " << std::endl;

	f.read(s, N);

	int cnt = 0;
	for (int i = 0; i < N; ++i) {
		if (s[i] == '1') {
			// g << i << std::endl;
			++cnt;
		}
	}

	
	std::cout << "Num 1s found: " << cnt << std::endl;
	
	return 0;
}
		

	

#include <iostream>
#include <vector>

const int N = int(1e6);
const int EDGES_PER_NODE = 5;

int Edges[N][EDGES_PER_NODE];
int Queue[N];
bool visited[N];

void generate_graph()
{
	for (int i = 0; i < N; ++i) {
		int x = i;
		for (int j = 0; j < EDGES_PER_NODE; ++j) {
			Edges[i][j] = x;
			x += 100;
			x %= N;
		}
	}
}

int compute_CCs()
{
	int ccs = 0;
	for (int i = 0; i < N; ++i) {
		if (visited[i]) {
			continue;
		}
		
		++ccs;

		visited[i] = 1;

		int front = 0;
		int back = 0;
		Queue[front] = i;
	
		while (front <= back) {
			int x = Queue[front++];
			for (int i = 0; i < EDGES_PER_NODE; ++i) {
				int y = Edges[x][i];
				if (visited[y]) {
					continue;
				}
	
				Queue[++back] = y;
				visited[y] = 1;
			}
		}
	}

	return ccs;
}


int main()
{
	std::cout << "Computing number of connected components for graph of size = " << N << std::endl;
	generate_graph();
	int ccs = compute_CCs();
	
	std::cout << "Number of connected components: " << ccs << std::endl;
	
	return 0;
}

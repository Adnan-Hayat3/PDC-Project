#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include "detector.h"

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);

    int rank = 0;
    int size = 0;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 2) {
        if (rank == 0) {
            printf("Usage: mpirun -np <N> ./ddos_detector <data_root>\n");
            printf("Example: mpirun -np 4 ./ddos_detector data\n");
        }
        MPI_Finalize();
        return 0;
    }

    const char *dataset_root = argv[1];

    if (size < 2) {
        if (rank == 0) {
            fprintf(stderr, "Need at least 2 MPI processes "
                            "(1 coordinator + 1 worker)\n");
        }
        MPI_Finalize();
        return 0;
    }

    if (rank == 0) {
        coordinator_start(size, dataset_root);
    } else {
        worker_start(rank, size, dataset_root);
    }

    MPI_Finalize();
    return 0;
}

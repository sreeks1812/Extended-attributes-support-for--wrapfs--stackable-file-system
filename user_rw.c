#include <stdio.h>
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

int main(void) {
	FILE *fp;
	int i;
	
	// plain open and closing a file
	fp=fopen("/n/scratch/samplefile.txt", "r");
	if(!fp) {
		perror("Error occured while opening the file");
		return -1;
	}
	fclose(fp);
	
	printf("plain open and closing a file - worked fine\n");
	
	/* initialize random seed: */
	srand (time(NULL));
  
	// open, write and close - I think this should handle truncate!
	fp=fopen("/n/scratch/samplefile.txt", "w");
	if(!fp) {
		perror("Error occured while opening the file");
		return -1;
	}
	for (i=0; i<=10; ++i)
        fprintf(fp, "%d, %d\n", i, rand() % 10);
	sleep(30);
	fclose(fp);
	
	printf("open, write (at the begining of the file) and close - worked fine\n");
	
	// open, close()
	fp=fopen("/n/scratch/samplefile.txt", "r");
	if(!fp) {
		perror("Error occured while opening the file");
		return -1;
	}
	fclose(fp);
	printf("plain open and closing a file - worked fine\n");
	
	fflush(stdout);
	return 0;
}

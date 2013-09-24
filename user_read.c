#include <stdio.h>
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

int main(void) {
	FILE *fp;
	int c;
	c = getc(fp) ;
   
	// plain open and closing a file
	fp=fopen("/n/scratch/samplefile.txt", "r");
	if(!fp) {
		perror("Error occured while opening the file");
		return -1;
	}
	
	while (c!= EOF)
	{
		putchar(c);
		c = getc(fp);
	}
	sleep(30);
	fclose(fp);
	
	return 0;

}

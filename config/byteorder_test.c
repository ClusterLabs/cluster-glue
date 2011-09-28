#include <stdio.h>

int
main ()
{
	unsigned int a = 0x1234;

	if ( (unsigned int) ( ((unsigned char *)&a)[0]) == 0x34 ) {
		printf("little-endian\n");
		return 0;
	} else {
		printf("big-endian\n");
		return 1;
	}	
}

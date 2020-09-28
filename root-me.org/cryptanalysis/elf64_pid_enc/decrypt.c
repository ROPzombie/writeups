#include <crypt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
 
int main()
{
		char pid[16];
			snprintf(pid, sizeof(pid), "%i", getpid());
				execl("ch21", "ch21", crypt(pid, "$1$awesome"), NULL);
}

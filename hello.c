#include <stdio.h>

int add(int a, int b)
{
	return a+b;
}

int main(int ac, char **av)
{
	add(0, ac);
	dprintf(1, "Hello World!\n");
}

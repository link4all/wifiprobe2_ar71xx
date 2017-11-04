#include <stdio.h>
#include <string.h>
char token[128]={0};
char gmac[16]={0};

void InitPar(){
	strcpy(gmac,"aa:aa:aa:aa:aa:aa");
	memset(token,0,sizeof(token));
	return;
}

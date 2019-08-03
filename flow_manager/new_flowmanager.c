#include "flowmanageer_log.h"
#include "time.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include <unistd.h>
#include "sys/wait.h"
#include <pthread.h>

#define SUCCESS 0
#define FAIL   -1

#define TCP_AND_UDP_RATE 0.95
#define LIMIT_FACTOR  0.95
#define DISLIMIT_FACTOR 0.9
#define BUFF_SIZE_256   256
#define BUFF_SIZE_1024  1024

#define CONF_FILE "flowmanager.conf"

#define IF_TRUE_RETURN(condiction,ret)   \
{\
	if(condiction)\
		return ret;\
}

#define IF_TRUE_RETURN_WITH_ERR(condiction,ret,mes)   \
{\
	if(condiction)\
	{\
		SYS_ERROR(mes);\
		return ret;\
	}\
}

typedef unsigned long int ullong;

typedef enum en_rate_limit
{
	NO_LIMIT_RATE = 0,
	LIMIT_UP_RATE,
	LIMIT_DOWN_RATE,
	LIMIT_RATE_BUFF
}rate_limit_e;

typedef enum en_strategy_action
{
	RM_UP_LIMIT  = 0,
	RM_DOWN_LIMIT,
	CHANGE_UP_LIMIT,
	ADD_UP_LIMIT,
	CHANGE_DOWN_LIMIT,
	ADD_DOWN_LIMIT,
	STRATEGY_ACTION_BUFF	
}strategy_action_e;

typedef struct st_limit_record
{
	ullong tcp_up_rate;
	ullong udp_up_rate;
	time_t up_time;
	ullong tcp_down_rate;
	ullong udp_down_rate;
	time_t down_time;
}limit_record_t;

typedef struct st_counter{
	ullong tcp_bit_counter;
	ullong tcp_packet_counter;
	ullong udp_bit_counter;
	ullong udp_packet_counter;
}counter_t;

pthread_mutex_t g_record_mutex;
ullong g_tcp_up_rate_record[6][336] = {0};
ullong g_tcp_down_rate_record[6][336] = {0};
ullong g_udp_up_rate_record[6][336] ={0};
ullong g_udp_down_rate_record[6][336] = {0};
ullong g_udp_down_predict_diff[5] = {0};
ullong g_udp_up_predict_diff[5]= {0};
ullong g_tcp_down_predict_diff[5] = {0};
ullong g_tcp_up_predict_diff[5]= {0};


time_t g_last_record_time = 0;
int   g_record_count = 0;

ullong g_up_bandwidth = 0;
ullong g_down_bandwidth = 0;
char g_wan_ifname[BUFF_SIZE_256] = {0};
char g_lan_ifname[BUFF_SIZE_256] = {0};

pthread_mutex_t g_rate_mutex;
ullong g_udp_up_rate = 0;
ullong g_tcp_up_rate = 0;
ullong g_tcp_down_rate = 0;
ullong g_udp_down_rate = 0;

/**************************************************
  * 函数名: str_2_ulonglong
  * 描述     : 将字符串转换成unsigned long long 类型
  *************************************************/
ullong str_2_ulonglong(char *str)
{
	ullong num = 0;

	while(*str == ' ')
	{
		str++;
	}

	while(*str <= '9' && *str>= '0')
	{
		num = num * 10 + (*str - '0');
		str++;
	}

	return num;
}
int do_cmd(const char *cmd)
{
	int status;

	IF_TRUE_RETURN_WITH_ERR(cmd==NULL, FAIL, "do cmd error:input cmd is NULL\n");
	
	status = system(cmd);
	if(status < 0)
	{
	    SYS_ERROR("cmd: %s\t error: %s", cmd, strerror(errno)); // 这里务必要把errno信息输出或记入Log
	    return FAIL;
	}

	if(WIFEXITED(status))
	{
	    //SYS_LOG("normal termination, exit status = %d\n", WEXITSTATUS(status)); //取得cmdstring执行结果
	}
	else if(WIFSIGNALED(status))
	{
 	   	SYS_ERROR("abnormal termination,signal number =%d\n", WTERMSIG(status)); //如果cmdstring被信号中断，取得信号值
	}
	else if(WIFSTOPPED(status))
	{
    		SYS_ERROR("process stopped, signal number =%d\n", WSTOPSIG(status)); //如果cmdstring被信号暂停执行，取得信号值
	}
	return SUCCESS;
}

int nft_counter_init(char *wan_ifname, char *lan_ifname)
{
	int ret = 0;
	char buf[BUFF_SIZE_256] = {0};

	do_cmd("nft flush table ip bytecounter");
	do_cmd("nft delete table ip bytecounter");
	
	ret = do_cmd("nft add table ip  bytecounter");
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	ret = do_cmd("nft add chain bytecounter forward{type filter hook forward priority 0\\;policy accept\\;}");
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	sprintf(buf, "nft add rule bytecounter forward ip protocol tcp oif %s counter",wan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	memset(buf, 0, BUFF_SIZE_256);
	sprintf(buf, "nft add rule bytecounter forward ip protocol udp oif %s counter",wan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	memset(buf, 0, BUFF_SIZE_256);
	sprintf(buf, "nft add rule bytecounter forward ip protocol tcp oif %s counter",lan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	memset(buf, 0, BUFF_SIZE_256);
	sprintf(buf, "nft add rule bytecounter forward ip protocol udp oif %s counter",lan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	return SUCCESS;
	
}


int nft_marker_init(char *wan_ifname, char *lan_ifname)
{
	int ret = 0;
	char buf[BUFF_SIZE_256] = {0};

	do_cmd("nft flush table ip marker");
	do_cmd("nft delete table ip marker");
	
	ret = do_cmd("nft add table ip marker");
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	ret = do_cmd("nft add chain marker forward{type filter hook forward priority 0\\;policy accept\\;}");
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	sprintf(buf, "nft add rule marker forward ip protocol tcp oif %s meta mark set 102",wan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	memset(buf, 0, BUFF_SIZE_256);
	sprintf(buf, "nft add rule marker forward ip protocol udp oif %s meta mark set 103",wan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	memset(buf, 0, BUFF_SIZE_256);
	sprintf(buf, "nft add rule marker forward ip protocol tcp oif %s meta mark set 112",lan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	memset(buf, 0, BUFF_SIZE_256);
	sprintf(buf, "nft add rule marker forward ip protocol udp oif %s meta mark set 113",lan_ifname);
	ret = do_cmd(buf);
	IF_TRUE_RETURN(ret == FAIL,FAIL);

	return SUCCESS;
	
}



int tc_limiter_init(char *wan_ifname, char *lan_ifname)
{
	int ret = 0;
	char buf[BUFF_SIZE_1024] = {0};

	sprintf(buf, "tc qdisc delete dev %s root",wan_ifname);
	do_cmd(buf);
	
	memset (buf,0, BUFF_SIZE_1024);
	sprintf(buf, "tc qdisc delete dev %s root",lan_ifname);
	do_cmd(buf);

	return SUCCESS;
	
}


int init_conf()
{
	FILE *fp;
	char buf[BUFF_SIZE_256] = {0};
	char *temp_p;
	int i = 0;
	int ret = 0;
	unsigned char flag = 0;
	
	fp=fopen(CONF_FILE, "r");
	IF_TRUE_RETURN_WITH_ERR(fp==NULL, FAIL, "open flowmanager config file fail!\n");

	while(flag != 0x0F  && NULL != fgets(buf,BUFF_SIZE_256,fp))
	{
		temp_p =strstr(buf, "wan_ifname");
		if(NULL != temp_p)
		{
			temp_p += strlen("wan_ifname");
			while(*temp_p == ' '){temp_p ++;}
			memset(g_wan_ifname, 0, BUFF_SIZE_256);
			while(*temp_p != ' ' && *temp_p != '\n')
			{
				g_wan_ifname[i] = *temp_p;
				temp_p ++;
				i++;
			}
			SYS_LOG("***get wan_ifname=%s\n", g_wan_ifname);
			flag |= 0x01;
		}
		else if(NULL != strstr(buf,"lan_ifname"))
		{
			temp_p = strstr(buf,"lan_ifname");
			temp_p += strlen("lan_ifname");
			while(*temp_p == ' '){temp_p ++;}
			memset(g_lan_ifname, 0, BUFF_SIZE_256);
			while(*temp_p != ' ' && *temp_p != '\n')
			{
				g_lan_ifname[i] = *temp_p;
				temp_p ++;
				i++;
			}
			SYS_LOG("***get lan_ifname=%s\n", g_lan_ifname);
			flag |= (1<<1);
		}
		else if(NULL != strstr(buf,"upload_bandwidth(Mbits)"))
		{
			temp_p = strstr(buf,"upload_bandwidth(Mbits)");
			temp_p += strlen("upload_bandwidth(Mbits)");
			g_up_bandwidth = str_2_ulonglong(temp_p);
			SYS_LOG("***get upload bandwidth=%ldMbits\n", g_up_bandwidth);
			g_up_bandwidth =g_up_bandwidth*1024*1024/8*TCP_AND_UDP_RATE;
			
			flag |= (1<<2);
		}
		else if(NULL != strstr(buf,"download_bandwidth(Mbits)"))
		{
			temp_p = strstr(buf,"download_bandwidth(Mbits)");
			temp_p += strlen("download_bandwidth(Mbits)");
			g_down_bandwidth = str_2_ulonglong(temp_p);
			SYS_LOG("***get download bandwidth=%ldMbits\n", g_down_bandwidth);
			g_down_bandwidth =g_down_bandwidth*1024*1024/8*TCP_AND_UDP_RATE;
			flag |= (1<<3);
		}
		i = 0;
		memset(buf, 0, BUFF_SIZE_256);		
	}

	fclose(fp);
	IF_TRUE_RETURN_WITH_ERR(flag!=0x0f, FAIL,"no enough para in conf file!\n");

	ret = nft_counter_init(g_wan_ifname, g_lan_ifname);
	IF_TRUE_RETURN(ret == FAIL, ret);
	
	ret = nft_marker_init(g_wan_ifname, g_lan_ifname);
	IF_TRUE_RETURN(ret == FAIL, ret);

	ret = tc_limiter_init(g_wan_ifname, g_lan_ifname);

	return ret;
	
}
int referren_data_read()
{
	FILE *fp;
	int i,j;

	fp = fopen("rate_record.txt","r");
	IF_TRUE_RETURN_WITH_ERR(fp == NULL, FAIL, "open rate record file fail!\n")

	for(i = 0; i <5; i++)
	{
		for(j = 0; j<336; j++)
		{
			IF_TRUE_RETURN_WITH_ERR((feof(fp)), FAIL, "fp is end!\n")
				
			fscanf(fp, "%lu %lu %lu %lu",&g_tcp_up_rate_record[i][j],&g_tcp_down_rate_record[i][j],
				&g_udp_up_rate_record[i][j],&g_udp_down_rate_record[i][j]);
		}
	}

	fclose(fp);
	
	return SUCCESS;
	
}


int referren_data_write()
{
	FILE *fp;
	int i,j;
	char buff[256] = {0};

	fp = fopen("rate_record.txt","w");
	IF_TRUE_RETURN_WITH_ERR(fp == NULL, FAIL, "open rate record file fail!\n")

	for(i = 0; i <5; i++)
	{
		for(j = 0; j<336; j++)
		{
			sprintf(buff,"%ld %ld %ld %ld ",g_tcp_up_rate_record[i][j],g_tcp_down_rate_record[i][j],
				g_udp_up_rate_record[i][j],g_udp_down_rate_record[i][j]);
			fputs(buff, fp);
			memset(buff, 0, 256);
		}
		fputs("\n",fp);
	}

	fclose(fp);
	
	return SUCCESS;
	
}

int init()
{
	int ret = 0;
	time_t temp_time;
	struct tm* time_p;

	ret = init_conf();
	IF_TRUE_RETURN((ret  == FAIL), ret);
	
	ret = referren_data_read();
	IF_TRUE_RETURN((ret  == FAIL), ret);

	time ( &temp_time );
	time_p = localtime ( &temp_time );

	g_last_record_time = 0;
	g_record_count = 0;

	g_udp_up_rate = 0;
	g_tcp_up_rate = 0;
	g_udp_down_rate = 0;
	g_tcp_down_rate = 0;

	pthread_mutex_init (&g_record_mutex,NULL);
	pthread_mutex_init (&g_rate_mutex,NULL);

	return SUCCESS;
}


unsigned int  is_need_to_limit()
{
	unsigned int limit = NO_LIMIT_RATE;

	pthread_mutex_lock (&g_rate_mutex);
	if((g_udp_up_rate + g_tcp_up_rate) >= (g_up_bandwidth * LIMIT_FACTOR))
	{
		SYS_LOG("need to limit UP rate\n");
		limit |= 1<<LIMIT_UP_RATE;
	}
	
	 if((g_udp_down_rate + g_tcp_down_rate) >= (g_down_bandwidth * LIMIT_FACTOR))
	{
		SYS_LOG("need to limit DOWN rate!\n");
		limit |= 1<<LIMIT_DOWN_RATE;
	}
	 
	pthread_mutex_unlock (&g_rate_mutex);
	return limit;
}

void  linear_fitting(double y[5], double* a, double* b)
{
	unsigned int max_index = 0;
	unsigned int min_index = 0;
	double  sumx = 0;
	double  sumy = 0;
	double  sumxy  = 0;
	double  sumxx = 0;
    double  avrx = 0;
	double  avry = 0;
	int i = 0;

	for(i = 0;i<5;i++)
	{
		if(y[i] >y[max_index])
		{
			max_index = i;
		}
		if(y[i]<y[min_index])
		{
			min_index = i;
		}
	}

	for(i = 0; i<5;i++)
	{
		if(i == max_index || i== min_index)
		{
			continue;
		}

		sumx += i;
		sumy += y[i];
		sumxy += i*y[i];
		sumxx += i*i;
	}

	avrx = sumx/3;
	avry = sumy/3;

	if(sumxx - 3*avrx*avrx == 0)
	{
		*a  =  0;
	}
	else
	{
		*a = (sumxy - 3*avrx*avry)/(sumxx - 3*avrx*avrx);
	}
	*b= avry - (*a)*avrx;
	
}


void get_new_limit_with_prediction(time_t cur_time, ullong *tcp_up_limit, 
	ullong *tcp_down_limit, ullong *udp_up_limit, ullong *udp_down_limit)
{
	double tcp_up_record[5] = {0};
	double tcp_down_record[5] = {0};
	double udp_up_record[5] = {0};
	double udp_down_record[5] = {0};
	double result = 0;
	int index = 0;
	int i = 0;
	double a = 0;
	double b = 0;
	struct tm * tm_p;

	tm_p = localtime(&cur_time);
	index= tm_p->tm_wday * 48 + tm_p->tm_hour*2 + (tm_p->tm_min/30);
	
	for(i = 0;i<5;i++)
	{
		tcp_up_record[i] = (double)g_tcp_up_rate_record[i][index];
		tcp_down_record[i] = (double)g_tcp_down_rate_record[i][index];
		udp_up_record[i] = (double)g_udp_up_rate_record[i][index];
		udp_down_record[i] = (double)g_udp_down_rate_record[i][index];
	}

	linear_fitting( tcp_up_record, &a, &b);
	result = (int)a*5+b;
	*tcp_up_limit = (result < 0) ? 0 : result;

	linear_fitting( tcp_down_record, &a, &b);
	result = a*5+b;
	*tcp_down_limit = (result < 0) ? 0 : result;

	linear_fitting( udp_up_record, &a, &b);
	result = a*5+b;
	*udp_up_limit = (result < 0) ? 0 : result;

	linear_fitting( udp_down_record, &a, &b);
	result = a*5+b;
	*udp_down_limit = (result < 0) ? 0 : result;
	
}

int get_counter_data(counter_t* up_counter_p, counter_t *down_counter_p)
{
	FILE *fp;
	char buf[BUFF_SIZE_256] = {0};
	char* temp_pack_p = NULL;
	char* temp_byte_p = NULL;
	int state = 0;

	fp = popen("nft list table bytecounter","r");
	if(fp == NULL)
	{
		SYS_ERROR("popen execute fail!\n");
		return FAIL;
	}
	while(state <4 && (fgets(buf, BUFF_SIZE_256, fp) != NULL))
	{
		temp_pack_p = strstr(buf,"ip protocol tcp oif eth0 counter packets ");
		if(temp_pack_p != NULL)
		{
			temp_byte_p = strstr(temp_pack_p,"bytes");
			if(temp_byte_p == NULL)
			{
				SYS_ERROR("get conmand return error format!\n");
				pclose(fp);
				return FAIL;
			}
			temp_pack_p += strlen("ip protocol tcp oif eth0 counter packets ");
			up_counter_p->tcp_packet_counter = str_2_ulonglong(temp_pack_p);
			temp_byte_p = temp_byte_p + strlen("bytes");
			up_counter_p->tcp_bit_counter = str_2_ulonglong(temp_byte_p);

			//SYS_LOG("!!!->%s P:%lu B:%lu\n",buf,up_counter_p->tcp_packet_counter,up_counter_p->tcp_bit_counter);

			state ++;
			continue;
		}

		temp_pack_p = strstr(buf,"ip protocol udp oif eth0 counter packets ");
		if(temp_pack_p != NULL)
		{
			temp_byte_p = strstr(temp_pack_p,"bytes");
			if(temp_byte_p == NULL)
			{
				SYS_ERROR("get conmand return error format!\n");
				pclose(fp);
				return FAIL;
			}
			temp_pack_p += strlen("ip protocol udp oif eth0 counter packets ");
			up_counter_p->udp_packet_counter = str_2_ulonglong(temp_pack_p);
			temp_byte_p = temp_byte_p + strlen("bytes");
			up_counter_p->udp_bit_counter = str_2_ulonglong(temp_byte_p);
			//SYS_LOG("!!!->%s P:%lu B:%lu\n",buf,up_counter_p->udp_packet_counter,up_counter_p->udp_bit_counter);
			state ++;
			continue;
		}

		temp_pack_p = strstr(buf,"ip protocol tcp oif eth1 counter packets");
		if(temp_pack_p != NULL)
		{
			temp_byte_p = strstr(temp_pack_p,"bytes");
			if(temp_byte_p == NULL)
			{
				SYS_ERROR("get conmand return error format!\n");
				pclose(fp);
				return FAIL;
			}
			temp_pack_p += strlen("ip protocol tcp oif eth1 counter packets");
			down_counter_p->tcp_packet_counter = str_2_ulonglong(temp_pack_p);
			temp_byte_p = temp_byte_p + strlen("bytes");
			down_counter_p->tcp_bit_counter = str_2_ulonglong(temp_byte_p);
			//SYS_LOG("!!!->%s P:%lu B:%lu\n",buf,down_counter_p->tcp_packet_counter,down_counter_p->tcp_bit_counter);

			state ++;
			continue;
		}

		temp_pack_p = strstr(buf,"ip protocol udp oif eth1 counter packets");
		if(temp_pack_p != NULL)
		{
			temp_byte_p = strstr(temp_pack_p,"bytes");
			if(temp_byte_p == NULL)
			{
				SYS_ERROR("get conmand return error format!\n");
				pclose(fp);
				return FAIL;
			}
			temp_pack_p += strlen("ip protocol udp oif eth1 counter packets ");
			down_counter_p->udp_packet_counter = str_2_ulonglong(temp_pack_p);
			temp_byte_p = temp_byte_p + strlen("bytes");
			down_counter_p->udp_bit_counter = str_2_ulonglong(temp_byte_p);

			//SYS_LOG("!!!->%s P:%lu B:%lu\n",buf,down_counter_p->udp_packet_counter,down_counter_p->udp_bit_counter);
			state ++;
		}
	}

	pclose(fp);

	if(state == 4)
	{
		return SUCCESS;
	}
	else
	{
		return FAIL;
	}
}

int handle_limit_strategy(strategy_action_e action, limit_record_t* limit_strategy)
{
	int ret;
	char buf[BUFF_SIZE_1024] = {0};
	
	if(action & (1<< RM_UP_LIMIT))
	{
		sprintf(buf, "tc qdisc delete dev %s root",g_wan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->rm up limit:%s\n",buf);
	}

	if(action &(1<<RM_DOWN_LIMIT))
	{
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc qdisc delete dev %s root",g_lan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->rm down limit:%s\n",buf);
	}

	if(action &(1<<CHANGE_UP_LIMIT))
	{
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class change dev %s parent 10:1 classid 10:2 cbq bandwidth %lubps rate %lubps allot  1514  prio 5 maxburst 20 avpkt 1000 bounded",
			g_wan_ifname,g_up_bandwidth,limit_strategy->tcp_up_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->change up limit1:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class change dev %s parent 10:1 classid 10:3 cbq bandwidth %lubps rate %lubps allot  1514 prio 5 maxburst 20 avpkt 1000 bounded",
			g_wan_ifname,g_up_bandwidth,limit_strategy->udp_up_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->change up limit2:%s\n",buf);
	}

	if(action &(1<<ADD_UP_LIMIT))
	{
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc qdisc add dev %s root handle 10: cbq bandwidth %lubps avpkt 1000",g_wan_ifname,g_up_bandwidth);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add up limit1:%s\n",buf);
		
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class add dev %s parent 10:0 classid 10:1 cbq bandwidth %lubps rate %lubps allot 1514  prio 8 maxburst 20 avpkt 1000",
			g_wan_ifname,g_up_bandwidth,g_up_bandwidth);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add up limit2:%s\n",buf);
		
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class add dev %s parent 10:1 classid 10:2 cbq bandwidth %lubps rate %lubps allot  1514  prio 5 maxburst 20 avpkt 1000 bounded",
			g_wan_ifname,g_up_bandwidth,limit_strategy->tcp_up_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add up limit3:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class add dev %s parent 10:1 classid 10:3 cbq bandwidth %lubps rate %lubps allot  1514  prio 5 maxburst 20 avpkt 1000 bounded",
			g_wan_ifname,g_up_bandwidth,limit_strategy->udp_up_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add up limit4:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc qdisc add dev %s parent 10:2 sfq quantum 1514b perturb 15",g_wan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add up limit5:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc filter add dev %s parent 10:0 protocol ip prio 1 handle 102 fw classid 10:2",g_wan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add up limit6:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc filter add dev %s parent 10:0 protocol ip prio 1 handle 103 fw classid 10:3",g_wan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add up limit7:%s\n",buf);
		
	}

	if(action &(1<<CHANGE_DOWN_LIMIT))
	{
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class change dev %s parent 11:1 classid 11:2 cbq bandwidth %lubps rate %lubps allot  1514  prio 5 maxburst 20 avpkt 1000 bounded",
			g_lan_ifname,g_down_bandwidth,limit_strategy->tcp_down_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->change down limit1:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class change dev %s parent 11:1 classid 11:3 cbq bandwidth %lubps rate %lubps allot  1514 prio 5 maxburst 20 avpkt 1000 bounded",
			g_lan_ifname,g_down_bandwidth,limit_strategy->udp_down_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->change down limit2:%s\n",buf);
	}

	if(action &(1<<ADD_DOWN_LIMIT))
	{
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc qdisc add dev %s root handle 11: cbq bandwidth %lubps avpkt 1000",g_lan_ifname,g_down_bandwidth);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add down limit1:%s\n",buf);
		
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class add dev %s parent 11:0 classid 11:1 cbq bandwidth %lubps rate %lubps allot 1514 prio 8 maxburst 20 avpkt 1000",
			g_lan_ifname,g_down_bandwidth,g_down_bandwidth);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add down limit2:%s\n",buf);
		
		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class add dev %s parent 11:1 classid 11:2 cbq bandwidth %lubps rate %lubps allot  1514  prio 5 maxburst 20 avpkt 1000 bounded",
			g_lan_ifname,g_down_bandwidth,limit_strategy->tcp_down_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add down limit3:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc class add dev %s parent 11:1 classid 11:3 cbq bandwidth %lubps rate %lubps allot  1514  prio 5 maxburst 20 avpkt 1000 bounded",
			g_lan_ifname,g_up_bandwidth,limit_strategy->udp_down_rate);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add down limit4:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc qdisc add dev %s parent 11:2 sfq quantum 1514b perturb 15",g_lan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add down limit5:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc filter add dev %s parent 11:0 protocol ip prio 1 handle 112 fw classid 11:2",g_lan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add down limit6:%s\n",buf);

		memset(buf, 0, BUFF_SIZE_1024);
		sprintf(buf, "tc filter add dev %s parent 11:0 protocol ip prio 1 handle 113 fw classid 11:3",g_lan_ifname);
		ret = do_cmd(buf);
		IF_TRUE_RETURN(ret == FAIL, ret);
		SYS_LOG("-------->add down limit7:%s\n",buf);
	}
	return SUCCESS;
}
int limit_self_adjust(limit_record_t *limit_strategy,rate_limit_e limit)
{
	int i;
	int ret = 0;
	rate_limit_e limit_action = 0;
	unsigned int strategy_action = 0;
	
	int add_tcp_up_count = 0;
	int add_udp_up_count = 0;
	int remove_up_count = 0;
	int add_tcp_down_count  = 0;
	int add_udp_down_count = 0;
	int remove_down_count = 0;

	ullong cur_tcp_up_rate = 0;
	ullong cur_udp_up_rate = 0;
	ullong cur_tcp_down_rate = 0;
	ullong cur_udp_down_rate = 0;

	long int add_tcp_up_diff = 0;
	long int add_udp_up_diff = 0;
	long int add_tcp_down_diff = 0;
	long int add_udp_down_diff = 0;
	time_t cur_time = 0;
	
	SYS_LOG("enter limit adjust\n");
	while(1==1)
	{
		sleep(10);
		
		pthread_mutex_lock (&g_rate_mutex);
		cur_tcp_up_rate = g_tcp_up_rate;
		cur_tcp_down_rate = g_tcp_down_rate;
		cur_udp_up_rate = g_udp_down_rate;
		cur_udp_down_rate = g_udp_down_rate;
		pthread_mutex_unlock (&g_rate_mutex);

		if(limit &(1<<LIMIT_UP_RATE))
		{
		
			if((cur_tcp_up_rate <(limit_strategy->tcp_up_rate * DISLIMIT_FACTOR)) && 
				(cur_udp_up_rate < (limit_strategy->udp_up_rate * DISLIMIT_FACTOR)))
			{
				add_tcp_up_count = 0;
				add_udp_up_count = 0;
				remove_up_count ++;
				add_tcp_up_diff  = 0;
				add_udp_up_diff = 0;
				SYS_LOG("remove_up_count ++;\n");
			}
			else if((cur_tcp_up_rate >= limit_strategy->tcp_up_rate* 0.99) &&
				( cur_udp_up_rate < limit_strategy->udp_up_rate*0.9))
			{
				add_tcp_up_diff += (limit_strategy->udp_up_rate - cur_udp_up_rate)/2;
				add_udp_up_diff = 0;
				add_tcp_up_count++;
				add_udp_up_count = 0;
				remove_up_count  = 0;
				SYS_LOG("add_tcp_up_count++;\n");
				
			}
			else if(cur_udp_up_rate >= limit_strategy->udp_up_rate * 0.99 
				&& cur_tcp_up_rate < limit_strategy->tcp_up_rate * 0.9)
			{
				add_udp_up_diff +=(limit_strategy->tcp_up_rate -cur_tcp_up_rate)/2;
				add_tcp_up_diff = 0;
				add_udp_up_count ++;
				add_tcp_up_count = 0;
				remove_up_count = 0;
				SYS_LOG("add_udp_up_count++;\n");
			}
			else
			{
				add_udp_up_diff =0;
				add_tcp_up_diff = 0;
				add_udp_up_count =0;
				add_tcp_up_count = 0;
				remove_up_count = 0;
				SYS_LOG("do up nothing\n");
			}
		}

		if(limit &(1<<LIMIT_DOWN_RATE))
		{
			if((cur_tcp_down_rate < (limit_strategy->tcp_down_rate* DISLIMIT_FACTOR)) &&
				(cur_udp_down_rate < (limit_strategy->udp_down_rate* DISLIMIT_FACTOR)))
			{
				add_tcp_down_count = 0;
				add_udp_down_count = 0;
				remove_down_count ++;
				add_tcp_down_diff  = 0;
				add_udp_down_diff = 0;
				SYS_LOG("remove_down_count++;\n");
			}
			else if((cur_tcp_down_rate >= limit_strategy->tcp_down_rate* 0.99) &&
				( cur_udp_down_rate < limit_strategy->udp_down_rate*0.9))
			{
				add_tcp_down_diff += (limit_strategy->udp_down_rate - cur_udp_down_rate)/2;
				add_udp_down_diff = 0;
				add_tcp_down_count++;
				add_udp_down_count = 0;
				remove_down_count  = 0;
				SYS_LOG("add_tcp_down_count++ add_tcp_down_diff=(%lu - %lu)/2=%ld;\n",limit_strategy->udp_down_rate,cur_udp_down_rate,add_tcp_down_diff);
				
			}
			else if(cur_udp_down_rate >= limit_strategy->udp_down_rate * 0.99 
				&& cur_tcp_down_rate < limit_strategy->tcp_down_rate * 0.9)
			{
				add_udp_down_diff +=(limit_strategy->tcp_down_rate -cur_tcp_down_rate)/2;
				add_tcp_down_diff = 0;
				add_udp_down_count ++;
				add_tcp_down_count = 0;
				remove_down_count = 0;
				SYS_LOG("add_udp_down_count++;\n");
			}
			else
			{
				add_udp_down_diff =0;
				add_tcp_down_diff = 0;
				add_udp_down_count =0;
				add_tcp_down_count = 0;
				remove_down_count = 0;
				SYS_LOG("do down nothing;\n");
			}
		}

		time(&cur_time);

		if(remove_up_count >= 3)
		{
			strategy_action |= 1<<RM_UP_LIMIT;
			remove_up_count = 0;
		}
		else if(add_tcp_up_count  >= 3)
		{
			if(limit_strategy->udp_up_rate - (add_tcp_up_diff/3) > g_up_bandwidth * 0.001)
			{
				if(limit & 1<< LIMIT_UP_RATE)
				{
					strategy_action |= 1<<CHANGE_UP_LIMIT;
				}
				else
				{
					limit |= 1<<LIMIT_UP_RATE;
					strategy_action |= 1<<ADD_UP_LIMIT;
				}

				limit_strategy->tcp_up_rate += (add_tcp_up_diff/3);
				limit_strategy->udp_up_rate -= (add_tcp_up_diff/3);
			}
			else
			{
				SYS_LOG("UDP up bandwidth will be too low ,won't add tcp up bandwidth\n");
			}
			add_tcp_up_count = 0;			
			add_tcp_up_diff = 0;
		}
		else if(add_udp_up_count >= 3)
		{
			if(limit_strategy->tcp_up_rate -  (add_udp_up_diff/3) > g_up_bandwidth*0.001)
			{
				if(limit & 1<<LIMIT_UP_RATE)
				{
					strategy_action |= (1<<CHANGE_UP_LIMIT);
				}
				else
				{
					limit |= 1<<LIMIT_UP_RATE;
					strategy_action |= (1<< ADD_UP_LIMIT);
				}
				limit_strategy->udp_up_rate += (add_udp_up_diff/3);
				limit_strategy->tcp_up_rate -=  (add_udp_up_diff/3);
			}
			else
			{
				SYS_LOG("TCP up bandwidth will be too low ,won't add udp up bandwidth\n");
			}
			add_udp_up_count = 0;
			
			add_udp_up_diff = 0;
		}


		if(remove_down_count >= 3)
		{
			strategy_action |= 1<<RM_DOWN_LIMIT;
			remove_down_count = 0;
		}
		else if(add_tcp_down_count  >= 3)
		{
			if(limit_strategy->udp_down_rate - (add_tcp_down_diff/3) >g_down_bandwidth*0.001)
			{
				if(limit & (1<<LIMIT_DOWN_RATE))
				{
					strategy_action |= 1<<CHANGE_DOWN_LIMIT;
				}
				else
				{
					limit |= 1<<LIMIT_DOWN_RATE;
					strategy_action |= 1<<ADD_DOWN_LIMIT;
				}
				limit_strategy->tcp_down_rate += (add_tcp_down_diff/3);
				limit_strategy->udp_down_rate -= (add_tcp_down_diff/3);
			}
			else
			{
				SYS_LOG("UDP down bandwidth will be too low ,won't add tcp down bandwidth\n");
			}
			add_tcp_down_count = 0;	
			add_tcp_down_diff = 0;

			SYS_LOG("----->tcp_down=%lu udp_down=%lu\n",limit_strategy->tcp_down_rate,limit_strategy->udp_down_rate);
		}
		else if(add_udp_down_count >= 3)
		{
			if(limit_strategy->tcp_down_rate -  (add_udp_down_diff/3) < g_down_bandwidth*0.001)
			{
				if(limit & (1<<LIMIT_DOWN_RATE))
				{
					strategy_action |= 1<<CHANGE_DOWN_LIMIT;
				}
				else
				{
					limit |= 1<<LIMIT_DOWN_RATE;
					strategy_action |= 1<< ADD_DOWN_LIMIT;
				}
				limit_strategy->udp_down_rate += (add_udp_down_diff/3);
				limit_strategy->tcp_down_rate -=  (add_udp_down_diff/3);
			}
			else
			{
				SYS_LOG("TCP down bandwidth will be too low ,won't add udp down bandwidth\n");
			}
			add_udp_down_count = 0;
			add_udp_down_diff = 0;
		}
		if(limit & (1<<LIMIT_UP_RATE))
		{
			limit_strategy->up_time = cur_time;
		}

		if(limit &(1<<LIMIT_DOWN_RATE))
		{
			limit_strategy ->down_time = cur_time;
		}
		

		if(strategy_action != 0)
		{
			ret = handle_limit_strategy(strategy_action, limit_strategy);
			IF_TRUE_RETURN((ret  == FAIL), ret);

			if(strategy_action & (1<<RM_DOWN_LIMIT))
			{
				limit &= (~(0x01 << LIMIT_DOWN_RATE));
			}

			if(strategy_action & (1<<RM_UP_LIMIT))
			{

				limit &=(~(0x01 << LIMIT_UP_RATE));
			}

			strategy_action = 0;
		}

		if(limit == NO_LIMIT_RATE)
		{
			SYS_LOG("exit limit adjust\n");
			return SUCCESS;
		}
		
	}
}
int enter_rate_limit (rate_limit_e limit)
{
	static limit_record_t limit_record = {0,0,0,0,0,0};
	
	struct tm* tm_p;	
	ullong tcp_up_limit = 0;
	ullong tcp_down_limit = 0;
	ullong udp_up_limit = 0;
	ullong udp_down_limit = 0;	
	time_t cur_time = 0;
	time_t predict_base_time = 0;
	time_t dtime[3] = {0};
	unsigned int  limit_action = 0;
	int ret = 0;
	double tcp_up_diff[5] = {0};
	double tcp_down_diff[5] = {0};
	double udp_up_diff[5] = {0};
	double udp_down_diff[5] = {0};
	double a = 0;
	double b = 0;
	
	
	int i;

	time(&cur_time);
	tm_p = localtime(&cur_time);

	SYS_LOG("enter limit state\n");
	pthread_mutex_lock (&g_record_mutex);
	if (limit & (1<<LIMIT_UP_RATE))
	{
		dtime[0] = cur_time - g_last_record_time;
		dtime[1] = 1800 - dtime[0];
		dtime[2] = cur_time - limit_record.up_time;
		
		if(dtime[1] < dtime[0] && dtime[1] < dtime[2])
		{
			get_new_limit_with_prediction(cur_time + 1800, &tcp_up_limit, &tcp_down_limit,
					&udp_up_limit, &udp_down_limit);
			for(i = 0; i<5;i++)
			{
				tcp_up_diff[i] = g_tcp_up_predict_diff[i];
				udp_up_diff[i] = g_udp_up_predict_diff[i];
			}
			linear_fitting(tcp_up_diff, &a,  &b);
			tcp_up_limit += a*5+b;
			tcp_up_limit = (tcp_up_limit <0) ? 0: tcp_up_limit;
			linear_fitting(udp_up_diff, &a,  &b);
			udp_up_limit += a*5+b;
			udp_up_limit = (udp_up_limit <0) ? 0: udp_up_limit;
		
			limit_record.tcp_up_rate = tcp_up_limit;
			limit_record.udp_up_rate = udp_up_limit;
		}
		else if(dtime[0] < dtime[1] && dtime[0] < dtime[2])
		{
			i =  tm_p->tm_wday * 48 + tm_p->tm_hour*2 + (tm_p->tm_min/30);
			limit_record.tcp_up_rate = g_tcp_up_rate_record[5][i];
			limit_record.udp_up_rate = g_udp_up_rate_record[5][i];
		}
		
		limit_record.up_time = cur_time;
	}

	if (limit & (1<<LIMIT_DOWN_RATE))
	{
		dtime[0] = cur_time - g_last_record_time;
		dtime[1] = 1800 - dtime[0];
		dtime[2] = cur_time - limit_record.down_time;

	 	if(dtime[1] < dtime[0] && dtime[1] < dtime[2])
		{
			get_new_limit_with_prediction(cur_time + 1800, &tcp_up_limit, &tcp_down_limit,
					&udp_up_limit, &udp_down_limit);
			for(i = 0; i<5;i++)
			{
				tcp_down_diff[i] = g_tcp_down_predict_diff[i];
				udp_down_diff[i] = g_tcp_down_predict_diff[i];
			}

			linear_fitting(tcp_down_diff, &a,  &b);
			tcp_down_limit += a*5+b;
			tcp_down_limit = (tcp_down_limit <0) ? 0: tcp_down_limit;

			linear_fitting(udp_down_diff, &a,  &b);
			udp_down_limit += a*5+b;
			udp_down_limit = (udp_down_limit <0) ? 0: udp_down_limit;
			
			limit_record.tcp_down_rate = tcp_down_limit;
			limit_record.udp_down_rate = udp_down_limit;
		}
		else if(dtime[0] < dtime[1] && dtime[0] < dtime[2])
		{
			i =  tm_p->tm_wday * 48 + tm_p->tm_hour*2 + (tm_p->tm_min/30);
			limit_record.tcp_down_rate = g_tcp_down_rate_record[5][i];
			limit_record.udp_down_rate = g_udp_down_rate_record[5][i];
		}
		
		limit_record.down_time = cur_time;
	}
	pthread_mutex_unlock (&g_record_mutex);

		
	if (limit & (1<<LIMIT_UP_RATE))
	{
		//避免出现其中一个为0的情况
		limit_record.tcp_up_rate ++;
		limit_record.udp_up_rate ++;
		
		limit_record.tcp_up_rate = g_up_bandwidth*limit_record.tcp_up_rate/(limit_record.tcp_up_rate + limit_record.udp_up_rate);
		limit_record.udp_up_rate = g_up_bandwidth - limit_record.tcp_up_rate;
		limit_record.up_time = cur_time;
		limit_action |= (1<<ADD_UP_LIMIT);
	}

	if( limit &(1<< LIMIT_DOWN_RATE))
	{
		//避免出现其中一个为0的情况
		limit_record.udp_down_rate++;
		limit_record.tcp_down_rate++;
		
		limit_record.tcp_down_rate = g_down_bandwidth*limit_record.tcp_down_rate/(limit_record.tcp_down_rate+limit_record.udp_down_rate);
		limit_record.udp_down_rate = g_down_bandwidth - limit_record.tcp_down_rate;
		limit_record.down_time = cur_time;
		limit_action |= (1 << ADD_DOWN_LIMIT);
	}

		
	if(limit_action > 0)
	{
			ret = handle_limit_strategy(limit_action,  &limit_record);
			IF_TRUE_RETURN((ret  == FAIL), ret);
	}
	sleep(2);
	
	ret = limit_self_adjust(&limit_record, limit);
	return ret;
		
}

int  add_rate_record(time_t time_now)
{
	int index;
	int i,j;
	ullong tcp_up_limit = 0;
	ullong tcp_down_limit = 0;
	ullong udp_up_limit = 0;
	ullong udp_down_limit  = 0;
	int ret = 0;
	
	struct tm * tm_p;

	tm_p = localtime(&time_now);	
	if(tm_p ->tm_min >= 30)
	{
		time_now = time_now - (tm_p->tm_min -30)*60 - tm_p->tm_sec;
	}
	else
	{
		time_now = time_now - (tm_p->tm_min)*60 - tm_p->tm_sec;
	}

	
			
	pthread_mutex_lock (&g_record_mutex);

	if(g_record_count == 336)
	{
		for(j = 0;j< 336;j++)
		{
			for(i=0;i<5;i++)
			{
				g_tcp_up_rate_record[i][j] = g_tcp_up_rate_record[i+1][j];
				g_tcp_down_rate_record[i][j] = g_tcp_down_rate_record[i+1][j];
				g_udp_up_rate_record[i][j] = g_udp_up_rate_record[i+1][j];
				g_udp_down_rate_record[i][j] = g_udp_down_rate_record[i+1][j];
			}
		}
		ret = referren_data_write();
		IF_TRUE_RETURN_WITH_ERR(ret == FAIL, ret, "write record data fail!\n");
		g_record_count = 0;
	}
	
	g_last_record_time = time_now;
	index= tm_p->tm_wday * 48 + tm_p->tm_hour*2 + (tm_p->tm_min/30);
	g_tcp_up_rate_record[5][index] = g_tcp_up_rate;
	g_tcp_down_rate_record[5][index] = g_tcp_down_rate;
	g_udp_up_rate_record[5][index] = g_udp_up_rate;
	g_udp_down_rate_record[5][index]=g_udp_down_rate;
	g_record_count ++;
	

	for(i =0;i<4;i++)
	{
		g_tcp_up_predict_diff[i] = g_tcp_up_predict_diff[i+1];
		g_tcp_down_predict_diff[i] = g_tcp_down_predict_diff[i+1];
		g_udp_up_predict_diff[i] = g_udp_up_predict_diff[i+1];
		g_udp_down_predict_diff[i] = g_udp_down_predict_diff[i+1];
	}
	get_new_limit_with_prediction(time_now, &tcp_up_limit, &tcp_down_limit,
		&udp_up_limit, &udp_down_limit);
	g_tcp_up_predict_diff[i] = g_tcp_up_rate - tcp_up_limit;
	g_tcp_down_predict_diff[i] = g_tcp_down_rate - tcp_down_limit;
	g_udp_up_predict_diff[i] = g_udp_up_rate - udp_up_limit;
	g_udp_down_predict_diff[i] = g_udp_down_rate - udp_down_limit;
	
	pthread_mutex_unlock(&g_record_mutex);
	//free(tm_p);
}

void flow_counter_pthread(void)
{
	int ret = 0;
	int index = 0;
	counter_t up_counter_old;
	counter_t up_counter_new;
	counter_t down_counter_old;
	counter_t down_counter_new;
	time_t time_old;
	time_t time_new;
	time_t time_diff;

	struct tm * tm_p;
	
	time(&time_old);

	ret = get_counter_data(&up_counter_old,& down_counter_old);
	if(ret == FAIL)
	{
		return;
	}
	SYS_LOG("adadad");

	while(1)
	{
		time(&time_new);
		ret = get_counter_data(&up_counter_new, &down_counter_new);
		if(ret == FAIL)
		{
			break;
		}

		time_diff=time_new-time_old;
		if(time_diff <= 0)
		{
			time_diff =1;
		}

		SYS_LOG("tcp : up:%lu packet/sec   %lu bytes/sec    udp : %lu packet/sec  %lu bytes/sec\n     down  %lu packet/sec   %lu bytes/sec    udp : %lu packet/sec  %lu bytes/sec\n",
			(up_counter_new.tcp_packet_counter  -  up_counter_old.tcp_packet_counter)/time_diff,
			(up_counter_new.tcp_bit_counter        -  up_counter_old.tcp_bit_counter)/time_diff,
			(up_counter_new.udp_packet_counter -  up_counter_old.udp_packet_counter)/time_diff,
			(up_counter_new.udp_bit_counter       -  up_counter_old.udp_bit_counter)/time_diff,
			(down_counter_new.tcp_packet_counter  -  down_counter_old.tcp_packet_counter)/time_diff,
			(down_counter_new.tcp_bit_counter        -  down_counter_old.tcp_bit_counter)/time_diff,
			(down_counter_new.udp_packet_counter -  down_counter_old.udp_packet_counter)/time_diff,
			(down_counter_new.udp_bit_counter       -  down_counter_old.udp_bit_counter)/time_diff);

		pthread_mutex_lock (&g_rate_mutex);
		g_tcp_up_rate     =(up_counter_new.tcp_bit_counter        -  up_counter_old.tcp_bit_counter)/time_diff;
		g_udp_up_rate    =(up_counter_new.udp_bit_counter       -  up_counter_old.udp_bit_counter)/time_diff;
		g_tcp_down_rate =(down_counter_new.tcp_bit_counter  -  down_counter_old.tcp_bit_counter)/time_diff;
		g_udp_down_rate=(down_counter_new.udp_bit_counter -  down_counter_old.udp_bit_counter)/time_diff;
		pthread_mutex_unlock(&g_rate_mutex);
		printf("tcp: -up %lu bytes/sec  -down %lu bytes/sec   udp: -up %lu bytes/sec  -down %lu bytes/sec\n", 
			g_tcp_up_rate,g_tcp_down_rate,g_udp_up_rate,g_udp_down_rate);

		memcpy(&up_counter_old, &up_counter_new, sizeof(up_counter_old));
		memcpy(&down_counter_old, &down_counter_new, sizeof(down_counter_old));
		time_old = time_new;

		if(time_new- g_last_record_time>= 1800)
		{
			ret = add_rate_record(time_new);
			if(ret == FAIL)
			{
				return ;
			}
		}

		
		sleep(1);
	}
}

int main()
{
	int ret = 0;
	rate_limit_e rate_limit = 0;
	pthread_t pid;
	

	SYS_LOG("flow manager start working!\n");
	SYS_LOG("init first!\n");
	ret = init();
	IF_TRUE_RETURN((ret  == FAIL), ret);
	SYS_LOG("init success!\n");
	
	
	
	SYS_LOG("create counter pthread!\n");
	ret=pthread_create(&pid,NULL,(void *) flow_counter_pthread,NULL);
	IF_TRUE_RETURN_WITH_ERR(ret != 0, FAIL, "Create pthread error!\n");
	
	while(1==1)
	{
		rate_limit = is_need_to_limit();
		if(rate_limit == NO_LIMIT_RATE)
		{
			sleep(2);
			continue;
		}

		ret = enter_rate_limit(rate_limit);
		IF_TRUE_RETURN((ret  == FAIL), ret);
	}

	return 0;
}


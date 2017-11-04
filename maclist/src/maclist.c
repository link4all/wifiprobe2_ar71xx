#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <sqlite3.h> 
#include <sys/time.h>
#include <time.h>
#include <linux/genetlink.h>
#include <json-c/json.h>
#include <pthread.h>
#include <sys/param.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <stdarg.h>
#include "debug.h"
#include "http.h"
#include "global.h"

#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))
#define DB_DIR "/root/test.db"
#define MAC_MAX 10000 //支持最大存储的mac数量
#define PATH "/sys/kernel/debug/ieee80211/phy0/netdev:wlan0/stations/"
#define HOSTNAME "xxx.com"

int nl_sd; /*the socket*/
unsigned char local_addr_num; //本次检测到的mac数量  数据类型要与内核保持一致
unsigned char all_addr_num;  //一共需要检测的mac数量
unsigned char maclist[MAC_MAX][7];
unsigned char cmac[100][7];
int flag_slc;
char mac_router[32];
sqlite3 *db;
struct {
	time_t fr_time;
	time_t last_time;
	unsigned char addr[6];
	char signal;
	char name[256];
	char isupdate;
}mac_list[MAC_MAX];

int str_replace(char* str,char* str_src, char* str_des){
    char *ptr=NULL;
    char buff[256];
    char buff2[256];
    int i = 0;
    
    if(str != NULL){
        strcpy(buff2, str);
    }   
    else{
            return -1; 
        }   

    memset(buff, 0x00, sizeof(buff));
    
    while((ptr = strstr( buff2, str_src)) !=0){
        if(ptr-buff2 != 0)  
                memcpy(&buff[i], buff2, ptr - buff2);
        memcpy(&buff[i + ptr - buff2], str_des, strlen(str_des));
		
        i += ptr - buff2 + strlen(str_des);
		
        strcpy(buff2, ptr + strlen(str_src));
    }   
    strcat(buff,buff2);
    strcpy(str,buff);
    return 0;
}

int get_mac(char *eth,char *mac_router)
{

    struct ifreq ifreq;
    int sock;

    if((sock=socket(AF_INET,SOCK_STREAM,0)) <0)
    {
	DEBUG_MSG("socket error！ 错误代码是%d，错误信息是'%s'\n",errno, strerror(errno));
        return   2;
    }

    strcpy(ifreq.ifr_name,eth);
    if(ioctl(sock,SIOCGIFHWADDR,&ifreq) <0)
    {
	DEBUG_MSG("ioctl error！ 错误代码是%d，错误信息是'%s'\n",errno, strerror(errno));
        return   3;
    }
    sprintf(mac_router,"%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[0],
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[1],
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[2],
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[3],
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[4],
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[5]);
	if(sock){
		close(sock);
	}
	return 0;
}

long int RunSysCmd(char *pCmd, char *pRslBuf, int bufSz){
    FILE *pFd = popen(pCmd, "r");
    int ret = 1;

    if(pFd){
        memset(pRslBuf, 0, bufSz);
        if(fgets(pRslBuf, bufSz-1, pFd)){
            if (pRslBuf[strlen(pRslBuf)-1] == 0x0a){
                pRslBuf[strlen(pRslBuf)-1] = '\0';
            }
            ret = 0;
        }
        pclose(pFd);
    }
    return ret;
}

int htconnect(char *host, int port){
        int white_sock;
        struct hostent * site;
        struct sockaddr_in me;
        site = gethostbyname(host);
        if (site==NULL) return -2;
        white_sock = socket(AF_INET,SOCK_STREAM,0);
        if (white_sock <0) return -1;
        memset(&me, 0, sizeof(struct sockaddr_in));
        memcpy(&me.sin_addr, site-> h_addr_list[0], site-> h_length);
        me.sin_family = AF_INET;
        me.sin_port = htons(port);
        return (connect(white_sock, (struct sockaddr *)&me,sizeof(struct sockaddr)) <0) ? -1 : white_sock;
}

int HTTP_GetContentLength(char *revbuf){
    char *p1 = NULL, *p2 = NULL;
    int HTTP_Body = 0;//内容体长度

   p1 = strstr(revbuf,"Content-Length");
    if(p1 == NULL)
        return -1;
    else
    {
        p2 = p1+strlen("Content-Length")+ 2;
        HTTP_Body = atoi(p2);
        return HTTP_Body;
    }

}

/*
 * Create a raw netlink socket and bind
 */
static int create_nl_socket(int protocol, int groups)
{
        socklen_t addr_len;
        int fd;
        struct sockaddr_nl local;
        
        fd = socket(AF_NETLINK, SOCK_RAW, protocol);
        if (fd < 0){
		perror("socket");
                return -1;
        }

        memset(&local, 0, sizeof(local));
        local.nl_family = AF_NETLINK;
        local.nl_groups = groups;
        if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
                goto error;
        
        return fd;
 error:
        close(fd);
        return -1;
}

/*
 * Send netlink message to kernel
 */
int sendto_fd(int s, const char *buf, int bufLen)
{
        struct sockaddr_nl nladdr;
        int r;
        
        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        
        while ((r = sendto(s, buf, bufLen, 0, (struct sockaddr *) &nladdr,
                           sizeof(nladdr))) < bufLen) {
                if (r > 0) {
                        buf += r;
                        bufLen -= r;
                } else if (errno != EAGAIN)
                        return -1;
        }
        return 0;
}


/*
 * Probe the controller in genetlink to find the family id
 * for the CONTROL_EXMPL family
 */
int get_family_id(int sd)
{
        struct {
                struct nlmsghdr n;
                struct genlmsghdr g;
                char buf[1024*2];
        } family_req;
        
        struct {
                struct nlmsghdr n;
                struct genlmsghdr g;
                char buf[1024*2];
        } ans;

        int id;
        struct nlattr *na;
        int rep_len;

        /* Get family name */
        family_req.n.nlmsg_type = GENL_ID_CTRL;
        family_req.n.nlmsg_flags = NLM_F_REQUEST;
        family_req.n.nlmsg_seq = 0;
        family_req.n.nlmsg_pid = getpid();
        family_req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
        family_req.g.cmd = CTRL_CMD_GETFAMILY;
        family_req.g.version = 0x1;
        
        na = (struct nlattr *) GENLMSG_DATA(&family_req);
        na->nla_type = CTRL_ATTR_FAMILY_NAME;
        /*------change here--------*/
        na->nla_len = strlen("STAMAC") + 1 + NLA_HDRLEN;
        strcpy(NLA_DATA(na), "STAMAC");
        
        family_req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

        if (sendto_fd(sd, (char *) &family_req, family_req.n.nlmsg_len) < 0)
		return -1;
    
	rep_len = recv(sd, &ans, sizeof(ans), 0);
        if (rep_len < 0){
		perror("recv");
		return -1;
	}

        /* Validate response message */
        if (!NLMSG_OK((&ans.n), rep_len)){
		fprintf(stderr, "invalid reply message\n");
		return -1;
	}

        if (ans.n.nlmsg_type == NLMSG_ERROR) { /* error */
                fprintf(stderr, "received error\n");
                return -1;
        }

        na = (struct nlattr *) GENLMSG_DATA(&ans);
        na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
        if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
                id = *(__u16 *) NLA_DATA(na);
        }
        return id;
}

int send_msg(char *msg,int msg_len,int id){
        struct {
                struct nlmsghdr n;
                struct genlmsghdr g;
                char buf[256][6];
        } req;
        struct nlattr *na;
      
        /* Send command needed */
        req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
        req.n.nlmsg_type = id;
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_seq = 60;
        req.n.nlmsg_pid = getpid();
        req.g.cmd = 1;//DOC_EXMPL_C_ECHO;
        
        /*compose message*/
        na = (struct nlattr *) GENLMSG_DATA(&req);
        na->nla_type = 1; //DOC_EXMPL_A_MSG
        na->nla_len = msg_len+NLA_HDRLEN; //message length
        memcpy(NLA_DATA(na), msg, msg_len);
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

        /*send message*/
	struct sockaddr_nl nladdr;
        int r;
        
        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
    
	r = sendto(nl_sd, (char *)&req, req.n.nlmsg_len, 0,  
			  (struct sockaddr *) &nladdr, sizeof(nladdr));
}

int recv_msg(void){
	    struct {
                struct nlmsghdr n;
                struct genlmsghdr g;
                char buf[1024*2];
        } ans;
        struct nlattr *na;
	    unsigned char i;

	    int rep_len = recv(nl_sd, &ans, sizeof(ans), 0);

        /* Validate response message */
        if (ans.n.nlmsg_type == NLMSG_ERROR) { /* error */
                printf("error received NACK - leaving \n");
               	return -1;
        }
        if (rep_len < 0) {
               	printf("error receiving reply message via Netlink \n");
               	return -1;
        }
//      if (!NLMSG_OK((&ans.n), rep_len)) {
//              printf("invalid reply message received via Netlink\n");
//		        return -1;
//	    }

        rep_len = GENLMSG_PAYLOAD(&ans.n);
        /*parse reply message*/
        na = (struct nlattr *) GENLMSG_DATA(&ans);
        unsigned char * result = (unsigned char *)NLA_DATA(na);
	    memcpy(&local_addr_num, result,sizeof(local_addr_num));
	
		if(local_addr_num > 0 && local_addr_num <= 200 ){
			memcpy(maclist,result+sizeof(local_addr_num),local_addr_num*7);
			for(i=0;i<local_addr_num;i++){
			    char signal;

			    memcpy(&signal,maclist[i]+6,sizeof(char));
			}
		}
}

static int cb_select(void *pst, int argc, char **argv, char **azColName){
    int i;
	int position = *(int *)pst;

    for(i=0; i<argc; i++){
   	 	if((strcmp(azColName[i],"time1")==0) && (argv[i]!=NULL)){
			mac_list[position].fr_time = atol(argv[i]);
    	}
	}												    
	flag_slc = 1;
	return 0;
}

int set_time(int position,int flag){
	time_t now;

	time(&now);

	if(flag){
		mac_list[position].fr_time = mac_list[position].last_time = now;
	}else{
		mac_list[position].last_time = now;
	}
}

int handle_mac(int dnum,unsigned char dmac[][7]){
	time_t t;
	int i,j;
	char dat_mac[32];
    int flag=0;
    int old_addrsn;

	t=time(&t);

    old_addrsn = all_addr_num;
	if(dnum){
		for(i=0;i<dnum;i++){
			for(j=0;j<old_addrsn;j++){
				if(memcmp(mac_list[j].addr,dmac[i],6)==0){
					set_time(j,0);
                    flag = 1;
					break;
				}
			}
            if(!flag){
				if(all_addr_num >= MAC_MAX)
					return 0;
                memcpy(mac_list[all_addr_num].addr,dmac[i],6);
                memcpy(&(mac_list[all_addr_num].signal),dmac[i]+6,sizeof(char));
				set_time(all_addr_num,1);
                all_addr_num ++;
            }
		}
	}
	return 0;
}

void mac_str_to_hex(char *mac,unsigned char *dst){
	char buf[6][3]={0};
	char i;
	char *str;

	sscanf(mac,"%[0-9a-zA-Z]:%[0-9a-zA-Z]:%[0-9a-zA-Z]:%[0-9a-zA-Z]:%[0-9a-zA-Z]:%[0-9a-zA-Z]",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
	for(i=0;i<6;i++){
		dst[i] = (strtol(buf[i],&str,16) & 0x000000ff);
	}
}

int isdir(char *name)
{
    struct stat stbuf;

    if( lstat(name, &stbuf) < 0)  {
        DEBUG_MSG("stat: %s :%s\n",name, strerror(errno));
        return 0;
	}else
	    return (S_ISDIR(stbuf.st_mode))? 1 : 0 ;
}
										

//获取当前在线mac
void get_now_mac(int *MacN,unsigned char dmac[][7])
{
    DIR *dirp;
    struct dirent *dir;
    if(isdir(PATH)) {
        if( (dirp = opendir(PATH)) == NULL) {
            DEBUG_MSG("Error opening dir %s\tstrerror(errno):%s\n",PATH,strerror(errno));
            return;
        }
    }else
        return;
    *MacN=0;
    bzero(dmac, sizeof(dmac));
    while( (dir = readdir(dirp)) != NULL) {
		int len;
		len = strlen(dir->d_name);
		if(!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..") ) { }
		else {
			if(strlen(dir->d_name) == 17) {	 //文件名的长度与标准mac字符串的长度相等
				mac_str_to_hex(dir->d_name,dmac[*MacN]);
				dmac[*MacN][6]=0;
				(*MacN)++;
			}
        }
    }
    if(closedir(dirp) == -1){
            DEBUG_MSG("Error closing dir %s\tstrerror(errno):%s\n",PATH,strerror(errno));
	}
}

void upcurrymac(){
	int imac;
	int i;

	sleep(10);
	while(1){
		sleep(3);
		get_now_mac(&imac,cmac);
		handle_mac(imac,cmac);
	}
}
void init_time(void){
	FILE *file;
    char line[512];
	char *Startstr;

	while(1){
		file = popen("ntpdate cn.pool.ntp.org | grep \"adjust time server\"", "r");
		if (file != NULL) {
			if (fgets(line,512, file) != NULL) {
				Startstr = strstr(line,"adjust time server");
				if(Startstr){
					pclose(file);
					break;
				}
			}
			pclose(file);
		}
	}
}

void send_thread(){
	char url[512]={0};
	char url2[]="http://caosx.cn:8080/device/dev-data";
	char buf[1024]={0};

	InitPar();
	memset(gmac,0,sizeof(gmac));
	get_mac("br-lan",mac_router);
	sprintf(url, "http://caosx.cn:8080/device/dev-token?mac=%s",mac_router);
	
	while(1){
		if(strlen(token) != 32){
			HttpJson(url,NULL,GET);//获取token
		}else{//发送数据
			if(all_addr_num==0)
				continue;

			int i;
			json_object *pData = json_object_new_array();
			json_object *pRespObj = json_object_new_object();
			for(i=0;i<all_addr_num;i++){
				json_object *jvalue = json_object_new_object();
				struct tm tm_fr,tm_la;
				char fr_t[64]={0};
				char la_t[64]={0};
				char pmac[32]={0};
				char signal[16]={0};

				localtime_r(&mac_list[i].fr_time,&tm_fr);
				strftime(fr_t,sizeof(fr_t),"%Y-%m-%d %H:%M:%S",&tm_fr);
				localtime_r(&mac_list[i].last_time,&tm_la);
				strftime(la_t,sizeof(la_t),"%Y-%m-%d %H:%M:%S",&tm_la);
				sprintf(pmac,"%02X:%02X:%02X:%02X:%02X:%02X",
							mac_list[i].addr[0],mac_list[i].addr[1],mac_list[i].addr[2],mac_list[i].addr[3],mac_list[i].addr[4],mac_list[i].addr[5]);
				sprintf(signal,"%d",mac_list[i].signal);

				json_object_object_add(jvalue,"phoneDbm",
							json_object_new_string(signal));
				json_object_object_add(jvalue,"loginTime",
							json_object_new_string(fr_t));
				json_object_object_add(jvalue,"logoutTime",
							json_object_new_string(la_t));
				json_object_object_add(jvalue,"phomeMac",
							json_object_new_string(pmac));

				json_object_array_add(pData,jvalue);
			}
			json_object_object_add(pRespObj,"token",
						json_object_new_string(token));
			json_object_object_add(pRespObj,"mac",
						json_object_new_string(mac_router));
			json_object_object_add(pRespObj,"probes",pData);
			
			const char *pJsonStr = json_object_get_string(pRespObj);
			printf("------------\n%s\n------------\n\n",pJsonStr);
			HttpJson(url2,pJsonStr,POST);
            //all_addr_num = 0;
		}
		sleep(20);
	}
}

int main(){
	int i;
	pthread_t ptdid;
	int ret;

//	init_time();
//	sleep(60);

	DEBUG_INIT();

	ret=pthread_create(&ptdid,NULL,(void *)send_thread,NULL);
	if(ret != 0)
	{
		DEBUG_MSG("Create send_thread pthread error!\n");
		return;
	}else{
		DEBUG_MSG("Create send_thread pthread succeed!\n");
	}	
	
//	ret=pthread_create(&ptdid,NULL,(void *)upcurrymac,NULL);
//	if(ret != 0)
//	{
//		DEBUG_MSG("Create upcurrymac pthread error!\n");
//		return;
//	}else{
//		DEBUG_MSG("Create upcurrymac pthread succeed!\n");
//	}	
	
	memset(mac_list,0,sizeof(mac_list));
	all_addr_num=0;
	//init_db();
    nl_sd = create_nl_socket(NETLINK_GENERIC,0);
    if(nl_sd < 0){
          DEBUG_MSG("%s","create_nl_socket create failure\n");
          return 0;
    }
    int id = get_family_id(nl_sd);

	for(;;){
		send_msg("s",1,id); //发送s，开启内核对mac的记录,否则内核不为些应用服务
		recv_msg();
		handle_mac(local_addr_num,maclist);
		sleep(2);
	}

//    	sqlite3_close(db);
//        close(nl_sd);
       
}


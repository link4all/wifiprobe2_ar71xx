#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define SAVE_DAY 1 //日志文件保存SAVE_DAY天
#define LOG_DIR "/tmp/log" //日志保存路径
#define FNAME "maclist_"  //日志文件名前缀

FILE* debug_file;
void debug_close(void);

void switchsystime(char* strdst,unsigned long dday,char *nowtime)
{
        int i=0;
        time_t t;
        char p[5][64];
        char times[128];
	int year,mon,day;
       // char strdst[128];
        char* token;
        t=time(&t);

	t -= dday*24*60*60;

        strcpy(times,ctime(&t));
	strcpy(nowtime,times);
	nowtime[strlen(nowtime)-1]=0;

        token = strtok( times, " ");
         while( token != NULL )
        {
                strcpy(p[i],token);
                token = strtok( NULL, " ");
                i++;
        }

        if(strcmp(p[1],"Jan")==0){
                strcpy(p[1],"01");
        }else if(strcmp(p[1],"Feb")==0){
                strcpy(p[1],"02");
        }else if(strcmp(p[1],"Mar")==0){
                strcpy(p[1],"03");
        }else if(strcmp(p[1],"Apr")==0){
                strcpy(p[1],"04");
        }else if(strcmp(p[1],"May")==0){
                strcpy(p[1],"05");
        }else if(strcmp(p[1],"Jun")==0){
                strcpy(p[1],"06");
        }else if(strcmp(p[1],"Jul")==0){
                strcpy(p[1],"07");
        }else if(strcmp(p[1],"Aug")==0){
                strcpy(p[1],"08");
        }else if(strcmp(p[1],"Sep")==0){
                strcpy(p[1],"09");
        }else if(strcmp(p[1],"Oct")==0){
                strcpy(p[1],"10");
        }else if(strcmp(p[1],"Nov")==0){
                strcpy(p[1],"11");
        }else if(strcmp(p[1],"Dec")==0){
                strcpy(p[1],"12");
        }

        p[4][4]=0;
        p[1][2]=0;
        p[2][2]=0;

        sprintf(strdst,"%s%s%s",p[4],p[1],p[2]);
        return ;
}


void debug_init(void)
{
   char log_filename[128]={0};
   char log_date[64]={0};
   char now_date[128]={0};
   char sys_cmd[128]={0};
   int i;

   for(i=0;i<100;i++){
   	memset(log_date,0,sizeof(log_date));
   	memset(log_filename,0,sizeof(log_filename));
   	memset(now_date,0,sizeof(now_date));

	switchsystime(log_date,SAVE_DAY+i+1,now_date);
   	sprintf(log_filename,"%s/%s%s",LOG_DIR,FNAME,log_date);
	if(access(log_filename,F_OK)==0){
		sprintf(sys_cmd,"rm -f %s",log_filename);
		system(sys_cmd);
	}
   }
  
   memset(log_date,0,sizeof(log_date));
   memset(log_filename,0,sizeof(log_filename));
   memset(now_date,0,sizeof(now_date));
   memset(sys_cmd,0,sizeof(sys_cmd));
   debug_file = NULL;

   switchsystime(log_date,0,now_date);
   sprintf(log_filename,"%s/%s%s",LOG_DIR,FNAME,log_date);
   sprintf(sys_cmd,"mkdir -p %s",LOG_DIR);
   system(sys_cmd);
   
   if ((debug_file = fopen (log_filename, "a")) == NULL)
  	return ;
 
   fprintf (debug_file, "\n======================%s=======================\n\n",now_date);

   fflush(debug_file);
   
   atexit(debug_close);
}

void debug_close(void)
{
   fprintf (debug_file, "\n\nDEVICE CLOSED FOR DEBUGGING\n\n");
   fflush(debug_file);
   fclose (debug_file);
   /* set it to null and check from other threads */
   debug_file = NULL;
}

void debug_msg(const char *message, ...)
{
   va_list ap;
   char log_date[64]={0};
   char now_date[128]={0};
   char debug_message[strlen(message)+2];

   /* if it was closed by another thread on exit */
   if (debug_file == NULL)
      return;

   switchsystime(log_date,0,now_date);
   fprintf(debug_file, "[%s]\t", now_date);

   strlcpy(debug_message, message, sizeof(debug_message));
   strlcat(debug_message, "\n", sizeof(debug_message));

   va_start(ap, message);
   vfprintf(debug_file, debug_message, ap);
   va_end(ap);

   fflush(debug_file);
}

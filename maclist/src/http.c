#include <curl/curl.h>  
#include <string.h>  
#include <json-c/json.h>
#include "http.h"  
#include "global.h"

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	char recv[1024];
	json_object *pRoot;

	strcpy(recv,(char *)ptr);
	pRoot = json_tokener_parse(recv);
	if(pRoot){
		const char *pcode,*pdata,*pmsg;
		json_object *code = json_object_object_get(pRoot,"code");
		json_object *data = json_object_object_get(pRoot,"data");
		json_object *msg = json_object_object_get(pRoot,"msg");
		pcode = json_object_get_string(code);
		pdata = json_object_get_string(data);
		pmsg = json_object_get_string(msg);

		if(!strcmp(pcode,"0")){
			strcpy(token,pdata);
			printf("获取token%s:[%s]\n",pmsg,pdata);
		}
	}

	return size * nmemb;
}  
int HttpJson(char *url, char *reqs, enum RQFG _reqtype) 
{  
    CURL *pCurl = NULL;  
    CURLcode res;  
  
    // get a curl handle  
    pCurl = curl_easy_init();  
    if (NULL != pCurl)   
    {  
		char content[1024]={0};
		// 设置超时时间为1秒  
        curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 1);  
  
        curl_easy_setopt(pCurl, CURLOPT_URL, url);  
 
		curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, content); 
		if(_reqtype == POST){
			// 设置http发送的内容类型为JSON  
			struct curl_slist *plist = curl_slist_append(NULL,   
			        "Content-Type:application/json;charset=UTF-8");  
			curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, plist);  
  
			// 设置要POST的JSON数据  
			curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, reqs);  
		}else{
			curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, write_callback);		
		}
        // Perform the request, res will get the return code   
        res = curl_easy_perform(pCurl);  
        // Check for errors  
        if (res != CURLE_OK)   
        {  
			printf("curl_easy_perform() failed:%s\n", curl_easy_strerror(res));  
        }else{
			//printf("curl success!\n\n");
		}
 
	    long int retcode = 0;
		CURLcode code = curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE , &retcode);
		if ( (code == CURLE_OK) && retcode == 200 ){
			if(strncmp(content,"success",7) == 0){
				//iRet = PROC_SUCCESS;
			} else {
				//iRet = PROC_FAILED;
			}
		}

        // always cleanup  
        curl_easy_cleanup(pCurl);  
	}  
    return 0;  
}  

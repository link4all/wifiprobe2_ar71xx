#ifndef HTTP_H

#define HTTP_H
enum RQFG{GET,POST};
int HttpJson(char *url, char *reqs, enum RQFG _reqtype);   

#endif

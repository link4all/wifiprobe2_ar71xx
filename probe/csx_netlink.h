#ifndef CSX_NETLINK_H
#define CSX_NETLINK_H

#include <net/netlink.h> 

#define ADDR_LOCAL_NUMBER 200    //最多可保存的sta设备的mac数目
#define MAC_ADDR_LEN 7   //mac地址(6Byte)与信号强度(1Byte)的长度

extern unsigned char GLOBAL_IsScan;    //为1表示为应用层存储sta设备mac，为0表示不记录sta设备mac
extern unsigned char GLOBAL_AddrLocalNum;  //当前共记录到的sta设备mac总数
extern unsigned char GLOBAL_AddrLocal[ADDR_LOCAL_NUMBER][MAC_ADDR_LEN];//用于存储sta设备的mac

extern int csx_netlink_init(void);
extern void csx_netlink_exit(void);


#endif

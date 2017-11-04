#include <linux/init.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include "csx_netlink.h"
/* attributes (variables): the index in this enum is used as a reference for the type,
 *             userspace application has to indicate the corresponding type
 *             the policy is used for security considerations 
 */

unsigned char GLOBAL_IsScan;
unsigned char GLOBAL_AddrLocalNum;
unsigned char GLOBAL_AddrLocal[ADDR_LOCAL_NUMBER][MAC_ADDR_LEN];

enum {
	DOC_EXMPL_A_UNSPEC,
	DOC_EXMPL_A_MSG,
	DOC_EXMPL_A_DAT,
        __DOC_EXMPL_A_MAX,
};
#define DOC_EXMPL_A_MAX (__DOC_EXMPL_A_MAX - 1)

/* attribute policy: defines which attribute has which type (e.g int, char * etc)
 * possible values defined in net/netlink.h 
 */
static struct nla_policy doc_exmpl_genl_policy[DOC_EXMPL_A_MAX + 1] = {
//	[DOC_EXMPL_A_MSG] = { .type = NLA_NUL_STRING },
	[DOC_EXMPL_A_DAT] = { .type = NLA_UNSPEC },
};

#define VERSION_NR 1
/* family definition */
static struct genl_family doc_exmpl_gnl_family = {
	.id = GENL_ID_GENERATE,         //genetlink should generate an id
	.hdrsize = 0,
	.name = "STAMAC",        //the name of this family, used by userspace application
	.version = VERSION_NR,                   //version number  
	.maxattr = DOC_EXMPL_A_MAX,
};

/* commands: enumeration of all commands (functions), 
 * used by userspace application to identify command to be ececuted
 */
enum {
	DOC_EXMPL_C_UNSPEC,
	DOC_EXMPL_C_ECHO,
	__DOC_EXMPL_C_MAX,
};
#define DOC_EXMPL_C_MAX (__DOC_EXMPL_C_MAX - 1)


/* an echo command, receives a message, prints it and sends another message back */
int doc_exmpl_echo(struct sk_buff *skb, struct genl_info *info)
{
    struct nlattr *na;
    int rc;
	void *msg_head;
	char * mydata;
	unsigned char snd_buff[1024];
	
    if (info == NULL)
		goto out;
 
	struct nlmsghdr		*nlhdr;
	struct genlmsghdr	*genlhdr;
	struct nlattr		*nlh;
	char	*str;

    struct sk_buff *skb_p;

	nlhdr	= nlmsg_hdr(skb);
	genlhdr	= nlmsg_data(nlhdr);
	nlh		= genlmsg_data(genlhdr);

	str		= (char *)nla_data(nlh);
	printk("getstr= %c\n",*str);
	if(*str == 's')
		GLOBAL_IsScan	= 1;
	else
		GLOBAL_IsScan	= 0;

    /* send a message back*/
    skb_p = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb_p == NULL)
		goto out;
    msg_head = genlmsg_put(skb_p, 0, info->snd_seq+1, &doc_exmpl_gnl_family, 0, DOC_EXMPL_C_ECHO);
	if (msg_head == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	printk("GLOBAL_AddrLocalNum= %u\n",GLOBAL_AddrLocalNum);
	memcpy(snd_buff,&GLOBAL_AddrLocalNum,sizeof(GLOBAL_AddrLocalNum));
	if(GLOBAL_AddrLocal > 0)
		memcpy(snd_buff+sizeof(GLOBAL_AddrLocalNum),GLOBAL_AddrLocal,GLOBAL_AddrLocalNum*MAC_ADDR_LEN);
	rc = nla_put(skb_p, DOC_EXMPL_A_DAT,sizeof(GLOBAL_AddrLocalNum)+GLOBAL_AddrLocalNum*MAC_ADDR_LEN,snd_buff);
	if (rc != 0)
		goto out;
	genlmsg_end(skb, msg_head);
	rc = genlmsg_unicast(genl_info_net(info), skb_p, info->snd_portid);
	GLOBAL_AddrLocalNum=0;
	printk("DATA sended!\n");
  
	return 0;

 out:
    printk("an error occured in doc_exmpl_echo:\n");

    return 0;
}
/* commands: mapping between the command enumeration and the actual function*/
#if 1
struct genl_ops doc_exmpl_gnl_ops_echo[] = {
	{
		.cmd = DOC_EXMPL_C_ECHO,
		.flags = 0,
		.policy = doc_exmpl_genl_policy,
		.doit = doc_exmpl_echo,
		.dumpit = NULL,
	},
};
#else
struct genl_ops doc_exmpl_gnl_ops_echo = {
	.cmd = DOC_EXMPL_C_ECHO,
	.flags = 0,
	.policy = doc_exmpl_genl_policy,
	.doit = doc_exmpl_echo,
	.dumpit = NULL,
};
#endif
int csx_netlink_init(void)
{
	int rc;
    printk("INIT GENERIC NETLINK EXEMPLE MODULE\n");
    GLOBAL_AddrLocalNum = 0; 
	GLOBAL_IsScan = 0;
    /*register new family*/
    rc = genl_register_family_with_ops(&doc_exmpl_gnl_family, doc_exmpl_gnl_ops_echo);
   	if (rc != 0)
	    goto failure;
	return 0;
	
failure:
        printk("an error occured while inserting the generic netlink example module\n");
	return -1;
	
	
}

void csx_netlink_exit(void)
{
    int ret;
    printk("EXIT GENERIC NETLINK EXEMPLE MODULE\n");
    /*unregister the functions*/

//	ret = genl_unregister_ops(&doc_exmpl_gnl_family, &doc_exmpl_gnl_ops_echo);
//	if(ret != 0){
//  	printk("unregister ops: %i\n",ret);
//  	return;
//	}
    /*unregister the family*/
	ret = genl_unregister_family(&doc_exmpl_gnl_family);
	if(ret !=0){
                printk("unregister family %i\n",ret);
    }
}


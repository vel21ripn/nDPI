#include <linux/kernel.h> /* Needed for KERN_ALERT       */
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>

#include "ndpi_config.h"
#include "ndpi_main.h"

#include "ndpi_private.h"

#include "ndpi_strcol.h"
#include "ndpi_main_common.h"
#include "ndpi_main_netfilter.h"
#include "ndpi_debug.h"

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
extern unsigned long  ndpi_lib_trace;

static struct dbg_ipt_names dbg_ipt_names [] = {
	{1 << DBG_TRACE_CT,"ct_start"},
	{1 << DBG_TRACE_PKT,"packet"},
	{1 << DBG_TRACE_NAT,"nat"},
	{1 << DBG_TRACE_CNT,"counters"},
	{1 << DBG_TRACE_FLOW_MEM,"ct_mem"},
	{1 << DBG_TRACE_HOSTNM,"hostname"},
	{1 << DBG_TRACE_TLS,"tls"},
	{1 << DBG_TRACE_JA4,"ja4"},
	{1 << DBG_TRACE_JA4MATCH,"ja4_match"},
	{1 << DBG_TRACE_EXCLUDE,"exclude"},
	{1 << DBG_TRACE_MATCH,"ipt_match"},
	{1 << DBG_TRACE_MATCH2,"ipt_match2"},
	{1 << DBG_TRACE_CACHE,"ct_cache"},
	{1 << DBG_TRACE_GUESSED,"guessed"},
	{1 << DBG_TRACE_DDONE,"dpi_done"},
	{1 << DBG_TRACE_DPI,"dpi"},
	{1 << DBG_TRACE_RE,"regex"},
	{1 << DBG_TRACE_TG1,"tgt_notmagic"},
	{1 << DBG_TRACE_TG2,"tgt_start"},
	{1 << DBG_TRACE_TG3,"tgt_flow_nat"},
	{1 << DBG_TRACE_SPROC,"procfs_set"},
	{1 << DBG_TRACE_SPROC_H,"procfs_set_host"},
	{1 << DBG_TRACE_SPROC_I,"procfs_set_ip"},
	{1 << DBG_TRACE_GPROC,"procfs_get"},
	{1 << DBG_TRACE_GPROC_H,"procfs_get_host"},
	{1 << DBG_TRACE_GPROC_H2,"procfs_get_host2"},
//	{1 << DBG_TRACE_GPROC_I,"procfs_get_ip"},
	{1 << DBG_TRACE_MATCH_CMD,"match_cmd"},
	{1 << DBG_TRACE_NETNS,"netns"},
	{1 << DBG_TRACE_CT_NC,"ct_nc"},
	{1 << DBG_TRACE_FLOW,"flow"},
}; // 27 < 32
#endif

/* debug functions */
void ndpi_ipt_debug_printf(u_int16_t protocol, struct ndpi_detection_module_struct *id_struct,
		ndpi_log_level_t log_level, const char *file_name,
		const char *func_name, unsigned line_number,
		const char * format, ...)
{
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	struct ndpi_net *n = id_struct ? id_struct->user_data : NULL;
//	if(!n || protocol >= NDPI_MAX_NUM_STATIC_BITMAP)
//		pr_info("ndpi_debug n=%d, p=%u, l=%s\n",n != NULL,protocol,
//				log_level < 5 ? dbl_lvl_txt[log_level]:"???");
	if(!n || protocol >= NDPI_MAX_NUM_STATIC_BITMAP) return;

	if(log_level+1 <= ( ndpi_lib_trace < n->debug_level[protocol] ?
			    ndpi_lib_trace : n->debug_level[protocol]))  {
		char buf[256];
		const char *short_fn;
        	va_list args;

		memset(buf, 0, sizeof(buf));
        	va_start(args, format);
		vsnprintf(buf, sizeof(buf)-1, format, args);
       		va_end(args);
		short_fn = strrchr(file_name,'/');
		if(!short_fn)
			short_fn = file_name;
		    else
			short_fn++;

		switch(log_level) {
		case NDPI_LOG_ERROR:
                	pr_info("E: P=%d %s:%d %s",protocol, short_fn, line_number, /*func_name,*/ buf);
			break;
		case NDPI_LOG_TRACE:
                	pr_info("T: P=%d %s:%d %s",protocol, short_fn, line_number, /*func_name,*/ buf);
			break;
		case NDPI_LOG_DEBUG:
                	pr_info("D: P=%d %s:%d %s",protocol, short_fn, line_number, /*func_name,*/ buf);
			break;
		case NDPI_LOG_DEBUG_EXTRA:
                	pr_info("D2: P=%d %s:%d %s",protocol, short_fn, line_number, /*func_name,*/ buf);
			break;
		default:
			;
		}
        }
#endif
}

void set_debug_trace( struct ndpi_net *n) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	int i;
	const char *t_proto;
	ndpi_debug_function_ptr dbg_printf = (ndpi_debug_function_ptr)NULL;
	if(ndpi_lib_trace)
	    for(i=0; i < NDPI_MAX_NUM_STATIC_BITMAP; i++) {
		if(!n->mark[i].mark && !n->mark[i].mask) continue;
		t_proto = ndpi_get_proto_by_id(n->ndpi_struct,i);
		if(t_proto) {
			if(!n->debug_level[i]) continue;
			dbg_printf = ndpi_ipt_debug_printf;
			break;
		}
	    }
	if(n->ndpi_struct->ndpi_debug_printf != dbg_printf) {
		pr_info("ndpi:%s debug message %s\n",n->ns_name,
			dbg_printf != NULL ? "ON":"OFF");
		set_ndpi_debug_function(n->ndpi_struct, dbg_printf);
	} else {
		if(ndpi_log_debug)
		  pr_info("ndpi:%s debug %s (not changed)\n",n->ns_name,
			n->ndpi_struct->ndpi_debug_printf != NULL ? "on":"off");
	}
#endif
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES

#define DBG_NAMES_CNT (sizeof(dbg_ipt_names)/sizeof(dbg_ipt_names[0]))

int dbg_ipt_opt(char *lbuf,size_t count) {
	size_t i,l;
	lbuf[0] = '\0';
	for(i=0,l=0; i < DBG_NAMES_CNT;i++) {
		l += snprintf(&lbuf[l],count - l,"%-20s %c\n",dbg_ipt_names[i].name,
				ndpi_log_debug & dbg_ipt_names[i].mask ? 'Y':'n');
		if(l >= count - 1 && i < DBG_NAMES_CNT-1) {
			pr_err("ndpi:%s buffer %d too small\n",__func__,(int)count);
			break;
		}
	}
	lbuf[l] = '\0';
	return l;
}

uint32_t dbg_ipt_opt_get(const char *lbuf) {
	size_t i;
	if(!strcmp(lbuf,"all")) return 0xffffffff;
	for(i=0; i < DBG_NAMES_CNT;i++) {
		if(!strcmp(lbuf,dbg_ipt_names[i].name)) return dbg_ipt_names[i].mask;
	}
	return 0;
}
#endif

// static void print_list_head(struct list_head *lh);
void print_ct_ndpi(struct nf_ct_ext_ndpi *ct_ndpi) {
	char f_buf[8],pr_buf[8],a_buf[128];
	struct timespec64 tm;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
        ktime_get_real_ts64(&tm);
#else
        ktime_get_coarse_real_ts64(&tm);
#endif
	if(!ct_ndpi) return;
	if(test_ipv6(ct_ndpi)) {
		strcpy(f_buf,"V6");
		sprintf(pr_buf,"%d",ct_ndpi->l4_proto);
	 	snprintf(a_buf,sizeof(a_buf), "%pI6c.%hu -> %pI6c.%hu",
			&ct_ndpi->flinfo.ip_s, ntohs(ct_ndpi->flinfo.sport),
			&ct_ndpi->flinfo.ip_d, ntohs(ct_ndpi->flinfo.dport));
	} else {
		strcpy(f_buf,"V4");
		switch(ct_ndpi->l4_proto) {
		  case 1:  strcpy(pr_buf,"ICMP"); 
			   break;
		  case 6:  strcpy(pr_buf,"TCP"); 
			   break;
		  case 17: strcpy(pr_buf,"UDP"); 
			   break;
		  default: sprintf(pr_buf,"%d",ct_ndpi->l4_proto);
		}
		snprintf(a_buf,sizeof(a_buf), "%pI4:%hu -> %pI4:%hu",
			&ct_ndpi->flinfo.ip_s, ntohs(ct_ndpi->flinfo.sport),
			&ct_ndpi->flinfo.ip_d, ntohs(ct_ndpi->flinfo.dport));
	}
	pr_info("ct_ndpi %8p %s %s %s %s%s%s%s%s%s\n",(void *)ct_ndpi,f_buf,pr_buf,a_buf,
			!ct_ndpi->ct_new           ? " ack":" new",
			ct_ndpi->del_confirm         ? " may_del":"",
			test_for_delete(ct_ndpi)     ? " for_del":" not_del",
			test_detect_done(ct_ndpi)    ? " dpi":" process",
			test_flow_info(ct_ndpi)      ? " data":" empty",
			test_flow_yes(ct_ndpi)       ? " flow":" no_flow"
			);

}
#if 0
static void print_list_head(struct list_head *lh) {
        struct nf_ct_ext_ndpi *entry,*next;
        int i = 0;
        pr_info("dump list: %8p %8p %8p\n",lh,lh->prev,lh->next);
        entry = list_first_entry_or_null(lh, struct nf_ct_ext_ndpi, list);
        for(; next = entry ? ( list_is_last(&entry->list,lh) ?
                                    NULL : list_next_entry(entry,list)) : NULL,
                        entry; entry = next ) {
                pr_info("> %8p %8p %8p %8p\n",(void *)entry,
                                (void *)entry->list.prev,(void *)entry->list.next,
                                (void*)entry);
		print_ct_ndpi(entry);
                i++;
        }
        pr_info("dump list elements: %d\n",i);
}
#endif


char *ct_info(const struct nf_conn * ct,char *buf,size_t buf_size,int dir) {
 const struct nf_conntrack_tuple *t;
 char b_proto[6];
 if(!ct) {
	 strscpy(buf," null ",buf_size-1);
	 return buf;
 }
 t = &ct->tuplehash[!dir ? IP_CT_DIR_ORIGINAL: IP_CT_DIR_REPLY].tuple;
 switch(t->dst.protonum) {
    case 1: strcpy(b_proto,"ICMP"); break;
    case 6: strcpy(b_proto,"TCP"); break;
    case 17: strcpy(b_proto,"UDP"); break;
    default: snprintf(b_proto,sizeof(b_proto),"%d",t->dst.protonum);
 }
 if(t->src.l3num == AF_INET6)
 	snprintf(buf,buf_size, "ipv6 %s %pI6c.%hu -> %pI6c.%hu %s",
		b_proto,
		&t->src.u3.all, ntohs(t->src.u.all),
		&t->dst.u3.all, ntohs(t->dst.u.all),
		!dir ? "DIR":"REV");
    else
 	snprintf(buf,buf_size, "ipv4 %s %pI4:%hu -> %pI4:%hu %s",
		b_proto,
		&t->src.u3.ip, ntohs(t->src.u.all),
		&t->dst.u3.ip, ntohs(t->dst.u.all),
		!dir ? "DIR":"REV");
 return buf;
}

void packet_trace(const struct sk_buff *skb,const struct nf_conn * ct,
	struct nf_ct_ext_ndpi *ct_ndpi,int ct_dir,const char *msg, const char *format, ...) {

  const struct iphdr *iph = ip_hdr(skb);
  char ndpi_info[32];
  char buf[256];
  char ct_buf[128];
  va_list args;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ipv6hdr *ip6h = ipv6_hdr(skb);

  if(ip6h && ip6h->version != 6) ip6h = NULL;
    else iph = NULL;
#endif

  memset(buf, 0, sizeof(buf));
  if(format && strchr(format,'%')) {
	va_start(args, format);
	vsnprintf(buf, sizeof(buf)-1, format, args);
	va_end(args);
  }

  ndpi_info[0] = 0;
  if(ct_ndpi) {
	snprintf(ndpi_info,sizeof(ndpi_info)-1," [%d,%d,%s] ",
		 ct_ndpi->proto.app_protocol, ct_ndpi->proto.master_protocol,
			ndpi_confidence_get_name(ct_ndpi->confidence));
  } else {
	snprintf(ndpi_info,sizeof(ndpi_info)-1,"[!ct_ndpi]");
  }
  ct_info(ct,ct_buf,sizeof(ct_buf)-1,ct_dir);
  if(iph) {
	if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
		 struct udphdr *udph = (struct udphdr *)(((const u_int8_t *) iph) + iph->ihl * 4);
		 char tcp_flags[8] = "";
		 if(iph->protocol == IPPROTO_TCP) {
			int f_i = 0;
			struct tcphdr *tcph = (struct tcphdr *)udph;
			if(tcph->syn) tcp_flags[f_i++]='S';
			if(tcph->fin) tcp_flags[f_i++]='F';
			if(tcph->rst) tcp_flags[f_i++]='R';
			if(f_i)       tcp_flags[f_i++]=' ';
			tcp_flags[f_i++]='\0';
		 }
		 pr_info("%-13s skb %8p ct %8p %s%slen %d%s%s\n",
			msg ? msg:"",(void *)skb,(void *)ct,ct_buf,tcp_flags,skb->len,ndpi_info,buf);
  	} else
		 pr_info("%-13s skb %8p ct %8p %s len %d%s%s\n",
			msg ? msg:"",(void *)skb,(void *)ct,ct_buf,skb->len,ndpi_info,buf);
  } else if(ip6h) {
	pr_info("%-13s skb %8p ct %8p %s len %d%s%s\n",
		msg ? msg:"",(void *)skb,(void *)ct,ct_buf,skb->len,ndpi_info,buf);

  }
}


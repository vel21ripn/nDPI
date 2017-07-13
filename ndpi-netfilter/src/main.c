/* 
 * main.c
 * Copyright (C) 2010-2012 G. Elian Gidoni <geg@gnu.org>
 *               2012 Ed Wildgoose <lists@wildgooses.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/time.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>

#define BT_ANNOUNCE 

#include "ndpi_main.h"
#include "xt_ndpi.h"

#include "../../config.h"
#include "../lib/third_party/include/ndpi_patricia.h"

/* Only for debug! */
//#define NDPI_KERNEL_MALLOC_TRACE

//#define NDPI_IPPORT_DEBUG
#ifdef NDPI_IPPORT_DEBUG
#undef DP
#define DP(fmt, args...) printk(fmt, ## args)
#define DBGDATA(a...) a;
#warning  "DEBUG code"
#else
#define DP(fmt, args...)
#define DBGDATA(a...)
#endif

#define COUNTER(a) (volatile unsigned long int)(a)++

#define NDPI_PROCESS_ERROR (NDPI_LAST_IMPLEMENTED_PROTOCOL+1)
#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF    89
#endif

static char dir_name[]="xt_ndpi";
static char info_name[]="info";
static char ipdef_name[]="ip_proto";
#ifdef NDPI_DETECTION_SUPPORT_IPV6
static char info6_name[]="info6";
#endif
#ifdef BT_ANNOUNCE
static char ann_name[]="announce";
#endif

static char proto_name[]="proto";


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)


#define PROC_REMOVE(pde,net) proc_remove(pde)
#else

#define PROC_REMOVE(pde,net) proc_net_remove(net,dir_name)

/* backport from 3.10 */
static inline struct inode *file_inode(struct file *f)
{
	return f->f_path.dentry->d_inode;
}
static inline void *PDE_DATA(const struct inode *inode)
{
	return PROC_I(inode)->pde->data;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
#define refcount_dec_and_test(a) atomic_sub_and_test((int) 1,(a))
#endif

// for testing only!
//#define USE_CONNLABELS

#if !defined(USE_CONNLABELS) && defined(CONFIG_NF_CONNTRACK_CUSTOM) && CONFIG_NF_CONNTRACK_CUSTOM > 0
#define NF_CT_CUSTOM
#else
#undef NF_CT_CUSTOM
#include <net/netfilter/nf_conntrack_labels.h>
#ifndef CONFIG_NF_CONNTRACK_LABELS
#error NF_CONNTRACK_LABELS not defined
#endif
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("G. Elian Gidoni <geg@gnu.org>, Vitaly E. Lavrov <vel21ripn@gmail.com>");
MODULE_DESCRIPTION("nDPI wrapper");
MODULE_ALIAS("ipt_ndpi");
MODULE_ALIAS("ipt_NDPI");


/* id tracking */
struct osdpi_id_node {
        struct rb_node node;
        struct kref refcnt;
	union nf_inet_addr ip;
	struct ndpi_id_struct ndpi_id;
};

struct ndpi_net {
	struct ndpi_detection_module_struct *ndpi_struct;
	struct rb_root osdpi_id_root;
	NDPI_PROTOCOL_BITMASK protocols_bitmask;
	atomic_t	protocols_cnt[NDPI_LAST_IMPLEMENTED_PROTOCOL+1];
	spinlock_t	id_lock;
	spinlock_t	ipq_lock; // for proto & patricia tree
	struct proc_dir_entry   *pde,
#ifdef NDPI_DETECTION_SUPPORT_IPV6
				*pe_info6,
#endif
#ifdef BT_ANNOUNCE
				*pe_ann,
#endif
				*pe_info,
				*pe_proto,
				*pe_ipdef;
	int		n_hash;
	int		gc_count;
	int		gc_index;
	int		labels_word;
        struct		timer_list gc;
	struct ndpi_mark {
		uint32_t	mark,mask;
	} mark[NDPI_LAST_IMPLEMENTED_PROTOCOL+1];
};

struct nf_ct_ext_ndpi {
	struct ndpi_flow_struct	*flow;
	struct ndpi_id_struct   *src,*dst;
	ndpi_protocol		proto; // 2 x 2 bytes
	spinlock_t		lock; // 2 bytes on 32bit, 4 bytes on 64bit
	uint8_t			l4_proto,
#if __SIZEOF_LONG__ != 4
				pad[7];
#else
				pad[1];
#endif
/* 
 * 32bit - 20 bytes, 64bit 40 bytes;
 */
} __attribute ((packed));

#ifndef NF_CT_CUSTOM
#define NF_LABEL_WORDS 2
#define MAGIC_CT 0xa55a
struct nf_ct_ext_labels { /* max size 128 bit */
	/* words must be first byte for compatible with NF_CONNLABELS
	 * kernels 3.8-4.7 has variable size of nf_ext_labels
	 * kernels 4.8 has fixed size of nf_ext_labels
	 * 32bit - 8 bytes, 64bit - 16 bytes
	 */
	uint8_t			words,pad1;
	uint16_t		magic;
#if __SIZEOF_LONG__ != 4
	uint8_t			pad2[4];
#endif
	struct nf_ct_ext_ndpi	*ndpi_ext;
} __attribute ((packed));
#endif

struct ndpi_cb {
	void		*last_ct;
	uint32_t	data[2];
} __attribute ((packed));

struct ndpi_port_range {
	uint16_t	start, end, // port range
			proto,	    // ndpi proto
			l4_proto;   // 0 - udp, 1 - tcp
};
typedef struct ndpi_port_range ndpi_port_range_t;

struct ndpi_port_def {
	int		  count[2]; // counter udp and tcp ranges
	ndpi_port_range_t p[0];     // udp and tcp ranges
};

static ndpi_protocol proto_null = NDPI_PROTOCOL_NULL;

static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };

static unsigned long  ndpi_log_debug=0;
static unsigned long  ndpi_log_trace=0;
static unsigned long  ndpi_mtu=1520;
static unsigned long  bt_log_size=128;
static unsigned long  bt_hash_size=0;
static unsigned long  bt_hash_tmo=1200;

static unsigned long  ndpi_size_flow_struct=0;
static unsigned long  ndpi_size_id_struct=0;
static unsigned long  ndpi_size_hash_ip4p_node=0;

static unsigned long  ndpi_jumbo=0;
static unsigned long  ndpi_falloc=0;
static unsigned long  ndpi_nskb=0;
static unsigned long  ndpi_lskb=0;
static unsigned long  ndpi_flow_c=0;
static unsigned long  ndpi_flow_d=0;
static unsigned long  ndpi_bt_gc=0;

static unsigned long  ndpi_p0=0;
static unsigned long  ndpi_p1=0;
static unsigned long  ndpi_p2=0;
static unsigned long  ndpi_p31=0;
static unsigned long  ndpi_p34=0;
static unsigned long  ndpi_p7=0;
static unsigned long  ndpi_p9=0;
static unsigned long  ndpi_pa=0;
static unsigned long  ndpi_pb=0;
static unsigned long  ndpi_pc=0;
static unsigned long  ndpi_pd=0;
static unsigned long  ndpi_pe=0;
static unsigned long  ndpi_pf=0;
static unsigned long  ndpi_pg=0;
static unsigned long  ndpi_ph=0;
static unsigned long  ndpi_pi=0;
static unsigned long  ndpi_pi1=0;
static unsigned long  ndpi_pi2=0;
static unsigned long  ndpi_pi3=0;
static unsigned long  ndpi_pi4=0;
static unsigned long  ndpi_pj=0;
static unsigned long  ndpi_pjc=0;
static unsigned long  ndpi_pk=0;

static unsigned long  ndpi_pl[11]={0,};
unsigned long  ndpi_btp_tm[20]={0,};


module_param_named(log_debug, ndpi_log_debug, ulong, 0600);
module_param_named(log_trace, ndpi_log_trace, ulong, 0600);
module_param_named(mtu, ndpi_mtu, ulong, 0600);

module_param_named(bt_log_size, bt_log_size, ulong, 0400);
module_param_named(bt_hash_size, bt_hash_size, ulong, 0400);
module_param_named(bt_hash_timeout, bt_hash_tmo, ulong, 0400);

module_param_named(ndpi_size_flow_struct,ndpi_size_flow_struct,ulong, 0400);
module_param_named(ndpi_size_id_struct,ndpi_size_id_struct,ulong, 0400);
module_param_named(ndpi_size_hash_ip4p_node,ndpi_size_hash_ip4p_node,ulong, 0400);

module_param_named(err_oversize, ndpi_jumbo, ulong, 0400);
module_param_named(err_skb_linear, ndpi_falloc, ulong, 0400);
module_param_named(skb_seg,	 ndpi_nskb, ulong, 0400);
module_param_named(skb_lin,	 ndpi_lskb, ulong, 0400);
module_param_named(flow_created, ndpi_flow_c, ulong, 0400);
module_param_named(flow_deleted, ndpi_flow_d, ulong, 0400);
module_param_named(bt_gc_count,  ndpi_bt_gc, ulong, 0400);

module_param_named(ipv4,         ndpi_p0, ulong, 0400);
module_param_named(ipv6,         ndpi_pa, ulong, 0400);
module_param_named(nonip,        ndpi_pb, ulong, 0400);
module_param_named(err_ip_frag_len, ndpi_p1, ulong, 0400);
module_param_named(err_bad_tcp_udp, ndpi_p2, ulong, 0400);
module_param_named(ct_confirm,   ndpi_p31, ulong, 0400);
module_param_named(err_add_ndpi, ndpi_p34, ulong, 0400);
module_param_named(non_tcpudp,   ndpi_p7, ulong, 0400);
module_param_named(max_parsed_lines, ndpi_p9, ulong, 0400);
module_param_named(id_num,	 ndpi_pc, ulong, 0400);
module_param_named(noncached,	 ndpi_pd, ulong, 0400);
module_param_named(err_prot_err, ndpi_pe, ulong, 0400);
module_param_named(err_prot_err1, ndpi_pf, ulong, 0400);
module_param_named(err_alloc_flow, ndpi_pg, ulong, 0400);
module_param_named(err_alloc_id, ndpi_ph, ulong, 0400);
module_param_named(cached,	 ndpi_pi,  ulong, 0400);
module_param_named(c_ct_not,	 ndpi_pi1, ulong, 0400);
module_param_named(c_skb_not,	 ndpi_pi2, ulong, 0400);
module_param_named(c_all_not,	 ndpi_pi3, ulong, 0400);
module_param_named(c_id_not,	 ndpi_pi4, ulong, 0400);
module_param_named(l4mismatch,	 ndpi_pj,  ulong, 0400);
module_param_named(l4mis_size,	 ndpi_pjc, ulong, 0400);
module_param_named(ndpi_match,	 ndpi_pk,  ulong, 0400);


unsigned long  ndpi_pto=0,
	       ndpi_ptss=0, ndpi_ptsd=0,
	       ndpi_ptds=0, ndpi_ptdd=0,
	       ndpi_ptussf=0,ndpi_ptusdr=0,
	       ndpi_ptussr=0,ndpi_ptusdf=0,
	       ndpi_ptudsf=0,ndpi_ptuddr=0,
	       ndpi_ptudsr=0,ndpi_ptuddf=0 ;
unsigned long 
	       ndpi_pusf=0,ndpi_pusr=0,
	       ndpi_pudf=0,ndpi_pudr=0,
	       ndpi_puo=0;

static int ndpi_net_id;
static inline struct ndpi_net *ndpi_pernet(struct net *net)
{
	        return net_generic(net, ndpi_net_id);
}

/* detection */
static u32 detection_tick_resolution = 1000;

static	enum nf_ct_ext_id nf_ct_ext_id_ndpi = 0;
static	struct kmem_cache *osdpi_flow_cache = NULL;
static	struct kmem_cache *osdpi_id_cache = NULL;
struct kmem_cache *bt_port_cache = NULL;

/* debug functions */

static void debug_printf(u32 protocol, void *id_struct,
                         ndpi_log_level_t log_level, const char *format, ...)
{
	char buf[1024];
	const char *extra_msg = "";
        va_list args;
	if(log_level < ndpi_log_trace) {
		if(log_level == NDPI_LOG_ERROR)
		      extra_msg = "ERROR: ";
		else if(log_level == NDPI_LOG_TRACE)
		      extra_msg = "TRACE: ";
		else
		      extra_msg = "DEBUG: ";

		memset(buf, 0, sizeof(buf));
        	va_start(args, format);
		vsnprintf(buf, sizeof(buf)-1, format, args);
       		va_end(args);
                printk(" %s PROTO: %d %s",extra_msg,protocol,buf);
        }
}

int inet_pton(int af, const char *src, void *dst) {
	struct in_addr *pin;
	const char *c;
	u32 a=0;
	int i;
	if(af != AF_INET) return -1; // EAFNOSUPPORT

	pin = dst;
	pin->s_addr = 0;
	c = src;
	for(i=0; i < 4; i++) {
	    int a0 = 0;
	    while(*c && *c >= '0' && *c <= '9') {
		    a0 *= 10;
		    a0 += *c - '0';
		    c++;
	    }
	    if(a0 > 255) return 0;
	    if(i == 3) {
		if(*c) return 0;
	    } else {
		if(*c != '.' ) return 0;
	    }
	    c++;
	    a <<= 8;
	    a |= a0;
	}
	pin->s_addr = ntohl(a);
	return 1;
}

static uint16_t ndpi_check_ipport(patricia_node_t *node,uint16_t port,int l4);
static char *ct_info(const struct nf_conn * ct,char *buf,size_t buf_size);

#ifdef NDPI_KERNEL_MALLOC_TRACE

static unsigned long  trace_alloc_mem=0;
module_param_named(trace_mem, trace_alloc_mem, ulong, 0600);

#define MAX_TRACE_ALLOC 16384
#define MAGIC_SIG 0xdefabeeful
static void *_x_alloc_mem[MAX_TRACE_ALLOC] = {NULL,};
static void *_x_alloc_mem_f[MAX_TRACE_ALLOC] = {NULL,};
static size_t _x_alloc_mem_s[MAX_TRACE_ALLOC] = {0,};
static int _x_alloc_mem_c=0;

void _add_alloc_mem(void *mem,size_t size,void *f) {
int i,j;
uint32_t *r;
for(i=0,j=-1; i < _x_alloc_mem_c; i++) {
	if(_x_alloc_mem[i]) {
		r = (uint32_t *)((char *)_x_alloc_mem[i] + _x_alloc_mem_s[i]);
		if(*r != MAGIC_SIG) {
			printk("%s: bad magic %p (%zu) %pS",
					__func__,_x_alloc_mem[i],
					_x_alloc_mem_s[i],
					_x_alloc_mem_f[i]);
			printk(" %pS\n",f);
		}
	} else {
		if(j < 0) j = i;
	}
}
if(j < 0) {
	if(_x_alloc_mem_c >= MAX_TRACE_ALLOC) {
		return;
	}
	j = _x_alloc_mem_c++;
}
r = (uint32_t *)((char *)mem + size);
*r = MAGIC_SIG;
_x_alloc_mem[j] = mem;
_x_alloc_mem_s[j] = size;
_x_alloc_mem_f[j] = f;
printk("TRACE MEM Alloc %d %p %zu %pS\n",j,mem,size,f);
}

void _del_alloc_mem(void *mem,void *f) {
int i,j;
uint32_t *r;

for(i=0,j=-1; i < _x_alloc_mem_c; i++) {
	if(_x_alloc_mem[i]) {
		r = (uint32_t *)((char *)_x_alloc_mem[i] + _x_alloc_mem_s[i]);
		if(*r != MAGIC_SIG) {
			printk("%s: BUG! bad magic %p (%zu) %pS from %pS\n",
					__func__,_x_alloc_mem[i],
					_x_alloc_mem_s[i],
					_x_alloc_mem_f[i],f);
		}
		if(_x_alloc_mem[i] == mem) {
			j = i;
		}
		if(j < 0) j = i;
	}
}
if(j < 0) {
	printk("%s: BUG! free nonalloc mem %p  %pS",
			__func__,mem,f);
} else {
	printk("TRACE MEM Free  %d %p %zu %pS\n",j,mem,_x_alloc_mem_s[j],f);
	_x_alloc_mem[j] = NULL;
	_x_alloc_mem_s[j] = 0;
	_x_alloc_mem_f[j] = NULL;
}
}

void _report_alloc_mem(void) {
int i,j;
uint32_t *r;
printk("%s: max alloc %d\n",__func__,_x_alloc_mem_c);
for(i=0,j=0; i < _x_alloc_mem_c; i++) {
	if(_x_alloc_mem[i]) {
		r = (uint32_t *)((char *)_x_alloc_mem[i] + _x_alloc_mem_s[i]);
		if(*r != MAGIC_SIG) {
			printk("%s: BUG! bad magic %p (%zu) %pS\n",
					__func__,_x_alloc_mem[i],
					_x_alloc_mem_s[i],
					_x_alloc_mem_f[i]);
		} else
			printk("%s: BUG! nonfree  %p (%zu) %pS\n",
					__func__,_x_alloc_mem[i],
					_x_alloc_mem_s[i],
					_x_alloc_mem_f[i]);
		j++;
	}
}
}

static void *malloc_wrapper(unsigned long size)
{
if(trace_alloc_mem) {
	void *ret = kmalloc(size+4, GFP_KERNEL);
	_add_alloc_mem(ret,size,__builtin_return_address(1));
	return ret;
}
return kmalloc(size, GFP_KERNEL);
}

static void free_wrapper(void *freeable)
{
if(trace_alloc_mem) {
	_del_alloc_mem(freeable,__builtin_return_address(1));
}
	kfree(freeable);
}

#else

static void *malloc_wrapper(unsigned long size)
{
	return kmalloc(size, GFP_KERNEL);
}

static void free_wrapper(void *freeable)
{
	kfree(freeable);
}

#define _report_alloc_mem()

#endif

static void fill_prefix_any(prefix_t *p, union nf_inet_addr *ip,int family) {
	memset(p, 0, sizeof(prefix_t));
	p->ref_count = 0;
	if(family == AF_INET) {
		memcpy(&p->add.sin, ip, 4);
		p->family = AF_INET;
		p->bitlen = 32;
		return;
	}
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	if(family == AF_INET6) {
		memcpy(&p->add.sin, ip, 16);
		p->family = AF_INET6;
		p->bitlen = 128;
	}
#endif
}

static struct ndpi_id_struct *
ndpi_id_search_or_insert(struct ndpi_net *n, 
		union nf_inet_addr *ip)
{
        int res;
        struct osdpi_id_node *this,*id;
	struct rb_root *root;
  	struct rb_node **new, *parent = NULL;

	spin_lock_bh (&n->id_lock);
	root = &n->osdpi_id_root;
	new  = &(root->rb_node);
  	while (*new) {
                this = rb_entry(*new, struct osdpi_id_node, node);
		res = memcmp(ip, &this->ip,sizeof(union nf_inet_addr));

		parent = *new;
  		if (res < 0)
  			new = &((*new)->rb_left);
  		else if (res > 0)
  			new = &((*new)->rb_right);
  		else {
                	kref_get (&this->refcnt);
			spin_unlock_bh (&n->id_lock);
  			return &this->ndpi_id;
		}
  	}
	id = kmem_cache_zalloc (osdpi_id_cache, GFP_ATOMIC);
	if (id == NULL) {
		spin_unlock_bh (&n->id_lock);
		pr_err("xt_ndpi: couldn't allocate new id.\n");
		return NULL;
	}
	(volatile unsigned long int)ndpi_pc++;
	memcpy(&id->ip, ip, sizeof(union nf_inet_addr));
	kref_init (&id->refcnt);

  	rb_link_node(&id->node, parent, new);
  	rb_insert_color(&id->node, root);
	spin_unlock_bh (&n->id_lock);
	return &id->ndpi_id;
}

static void
ndpi_free_id (struct ndpi_net *n, struct osdpi_id_node * id)
{
	if (refcount_dec_and_test(&id->refcnt.refcount)) {
	        rb_erase(&id->node, &n->osdpi_id_root);
	        kmem_cache_free (osdpi_id_cache, id);
		(volatile unsigned long int)ndpi_pc--;
	}
}

#ifdef NF_CT_CUSTOM
static inline struct nf_ct_ext_ndpi *nf_ct_ext_find_ndpi(const struct nf_conn * ct)
{
	return (struct nf_ct_ext_ndpi *)__nf_ct_ext_find(ct,nf_ct_ext_id_ndpi);
}
#else

static inline struct nf_ct_ext_ndpi *nf_ct_ext_find_ndpi(const struct nf_conn * ct)
{
struct nf_ct_ext_labels *l = (struct nf_ct_ext_labels *)__nf_ct_ext_find(ct,nf_ct_ext_id_ndpi);
return l && l->magic == MAGIC_CT ? l->ndpi_ext:NULL;
}

static inline struct nf_ct_ext_labels *nf_ct_ext_find_label(const struct nf_conn * ct)
{
	return (struct nf_ct_ext_labels *)__nf_ct_ext_find(ct,nf_ct_ext_id_ndpi);
}

#endif


#ifdef NF_CT_CUSTOM
static inline void *nf_ct_ext_add_ndpi(struct nf_conn * ct)
{
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	return nf_ct_ext_add(ct,nf_ct_ext_id_ndpi,GFP_ATOMIC);
  #elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	return __nf_ct_ext_add_length(ct,nf_ct_ext_id_ndpi,
		sizeof(struct nf_ct_ext_ndpi),GFP_ATOMIC);
  #else
	return __nf_ct_ext_add(ct,nf_ct_ext_id_ndpi,GFP_ATOMIC);
  #endif
}
#endif


static inline void ndpi_init_ct_struct(struct nf_ct_ext_ndpi *ct_ndpi,uint8_t l4_proto) {
	memset((char *)ct_ndpi,0,sizeof(struct nf_ct_ext_ndpi));
	spin_lock_init(&ct_ndpi->lock);
	ct_ndpi->l4_proto = l4_proto;
}

static int
__ndpi_free_flow (struct nf_conn * ct,void *data) {
	struct ndpi_net *n = data;
	struct nf_ct_ext_ndpi *ct_ndpi = nf_ct_ext_find_ndpi(ct);
	
	if(!ct_ndpi) return 1;

	spin_lock_bh (&n->id_lock);
	if(ct_ndpi->src) {
		ndpi_free_id (n, container_of(ct_ndpi->src,struct osdpi_id_node,ndpi_id ));
		ct_ndpi->src = NULL;
	}
	if(ct_ndpi->dst) {
		ndpi_free_id (n, container_of(ct_ndpi->dst,struct osdpi_id_node,ndpi_id ));
		ct_ndpi->dst = NULL;
	}
	spin_unlock_bh (&n->id_lock);

	if(ct_ndpi->flow != NULL) {
		ndpi_free_flow(ct_ndpi->flow);
		kmem_cache_free (osdpi_flow_cache, ct_ndpi->flow);
		ct_ndpi->flow = NULL;
		COUNTER(ndpi_flow_d);
		module_put(THIS_MODULE);
	}
	return 1;
}

static void
nf_ndpi_free_flow (struct nf_conn * ct)
{
	struct ndpi_net *n;
	struct nf_ct_ext_ndpi *ct_ndpi = nf_ct_ext_find_ndpi(ct);

	if(!ct_ndpi) return;
	if(ndpi_log_debug > 2) {
	    char ct_buf[128];
	    printk("Free_ct ct_ndpi %p ct %p %s\n",
					(void *)ct_ndpi,(void *)ct,
					ct_info(ct,ct_buf,sizeof(ct_buf)));
	}
	n = ndpi_pernet(nf_ct_net(ct));
	spin_lock_bh(&ct_ndpi->lock);
	__ndpi_free_flow(ct,(void *)n);
	spin_unlock_bh(&ct_ndpi->lock);
#ifndef NF_CT_CUSTOM
	{
	struct nf_ct_ext_labels *ext_l = nf_ct_ext_find_label(ct);
	if(ext_l && ext_l->ndpi_ext && ext_l->magic == MAGIC_CT) {
		ext_l->magic = 0;
		free_wrapper(ext_l->ndpi_ext);
		ext_l->ndpi_ext = NULL;
	}
	}
#endif
}

/* must be locked ct_ndpi->lock */
static struct ndpi_flow_struct * 
ndpi_alloc_flow (struct nf_ct_ext_ndpi *ct_ndpi)
{
        struct ndpi_flow_struct *flow;

        flow = kmem_cache_zalloc (osdpi_flow_cache, GFP_ATOMIC);
        if (flow == NULL) {
                pr_err("xt_ndpi: couldn't allocate new flow.\n");
                return flow;
        }

	ct_ndpi->proto = proto_null;
	ct_ndpi->flow = flow;
	__module_get(THIS_MODULE);
	COUNTER(ndpi_flow_c);
        return flow;
}
#ifndef NF_CT_CUSTOM
static void (*ndpi_nf_ct_destroy)(struct nf_conntrack *) __rcu __read_mostly;

static void ndpi_destroy_conntrack(struct nf_conntrack *nfct) {
	struct nf_conn *ct = (struct nf_conn *)nfct;
	void (*destroy)(struct nf_conntrack *);

	nf_ndpi_free_flow(ct);

	rcu_read_lock();
        destroy = rcu_dereference(ndpi_nf_ct_destroy);
        if(destroy) destroy(nfct);
        rcu_read_unlock();
}
#endif

/*****************************************************************/

static void
ndpi_enable_protocols (struct ndpi_net *n)
{
        int i,c=0;

        spin_lock_bh (&n->ipq_lock);
	if(atomic_inc_return(&n->protocols_cnt[0]) == 1) {
		for (i = 1,c=0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
			if(!n->mark[i].mark && !n->mark[i].mask)
				continue;
			NDPI_ADD_PROTOCOL_TO_BITMASK(n->protocols_bitmask, i);
			c++;
		}
		ndpi_set_protocol_detection_bitmask2(n->ndpi_struct,
				&n->protocols_bitmask);
	}
	spin_unlock_bh (&n->ipq_lock);
}


static void add_stat(unsigned long int n) {

	if(n > ndpi_p9) ndpi_p9 = n;
	n /= 10;
	if(n < 0) n = 0;
	if(n > sizeof(ndpi_pl)/sizeof(ndpi_pl[0])-1)
		n = sizeof(ndpi_pl)/sizeof(ndpi_pl[0])-1;
	ndpi_pl[n]++;
}

static char *ct_info(const struct nf_conn * ct,char *buf,size_t buf_size) {
 const struct nf_conntrack_tuple *t = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

 snprintf(buf,buf_size,"proto %u %pi4:%d -> %pi4:%d",
		t->dst.protonum,
		&t->src.u3.ip, ntohs(t->src.u.all),
		&t->dst.u3.ip, ntohs(t->dst.u.all));
 return buf;
}

static void packet_trace(const struct sk_buff *skb,const struct nf_conn * ct, char *msg) {
  const struct iphdr *iph = ip_hdr(skb);
  if(iph && iph->version == 4) {
	if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
		 struct udphdr *udph = (struct udphdr *)(((const u_int8_t *) iph) + iph->ihl * 4); 
		 printk("%s skb %p ct %p proto %d %pi4:%d -> %pi4:%d len %d\n",
			msg ? msg:"",(void *)skb,(void *)ct,
			iph->protocol,&iph->saddr,htons(udph->source),
			&iph->daddr,htons(udph->dest),skb->len);
  	} else
		 printk("%s skb %p ct %p proto %d %pi4 -> %pi4 len %d\n",
			msg ? msg:"",(void *)skb,(void *)ct,
			iph->protocol,&iph->saddr, &iph->daddr,skb->len);
  }
}

static u32
ndpi_process_packet(struct ndpi_net *n, struct nf_conn * ct, struct nf_ct_ext_ndpi *ct_ndpi,
		    const uint64_t time,
                    const struct sk_buff *skb,int dir)
{
	ndpi_protocol proto = NDPI_PROTOCOL_NULL;
	u_int16_t r_proto = NDPI_PROTOCOL_UNKNOWN;
        struct ndpi_id_struct *src, *dst;
        struct ndpi_flow_struct * flow;
	u32 low_ip, up_ip, tmp_ip;
	u16 low_port, up_port, tmp_port, protocol;
	const struct iphdr *iph = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	const struct ipv6hdr *ip6h;

	ip6h = ipv6_hdr(skb);
	if(ip6h && ip6h->version != 6) ip6h = NULL;
#endif
	iph = ip_hdr(skb);

	if(iph && iph->version != 4) iph = NULL;

	if(!iph
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		&& !ip6h
#endif
	  ) {
		COUNTER(ndpi_pf);
		return NDPI_PROCESS_ERROR;
	}

	flow = ct_ndpi->flow;
	if (!flow) {
		flow = ndpi_alloc_flow(ct_ndpi);
		if (!flow) {
			COUNTER(ndpi_pg);
			return NDPI_PROCESS_ERROR;
		}
	}

	src = ct_ndpi->src;
	if (!src) {
		src = ndpi_id_search_or_insert (n,
			&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3);
		if (!src) {
			COUNTER(ndpi_ph);
			return NDPI_PROCESS_ERROR;
		}
		ct_ndpi->src = src;
	}
	dst = ct_ndpi->dst;
	if (!dst) {
		dst = ndpi_id_search_or_insert (n,
			&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3);
		if (!dst) {
			COUNTER(ndpi_ph);
			return NDPI_PROCESS_ERROR;
		}
		ct_ndpi->dst = dst;
	}

	/* here the actual detection is performed */
	if(dir) {
		src = ct_ndpi->dst;
		dst = ct_ndpi->src;
	}

	flow->packet_direction = dir;
	if(ndpi_log_debug > 1)
		packet_trace(skb,ct,"process    ");
	proto = ndpi_detection_process_packet(n->ndpi_struct,flow,
#ifdef NDPI_DETECTION_SUPPORT_IPV6
				ip6h ?	(uint8_t *) ip6h :
#endif
					(uint8_t *) iph, 
					 skb->len, time, src, dst);

	if(proto.master_protocol == NDPI_PROTOCOL_UNKNOWN && 
	          proto.protocol == NDPI_PROTOCOL_UNKNOWN ) {
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	    if(ip6h) {
		low_ip = 0;
		up_ip = 0;
		protocol = ip6h->nexthdr;
	    } else
#endif
	    {
		low_ip=ntohl(iph->saddr);
		up_ip=ntohl(iph->daddr);
		protocol = iph->protocol;
	    }

	    if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
		low_port = htons(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port);
		up_port  = htons(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port);
	    } else {
		low_port = up_port = 0;
	    }
	    if (iph && flow && flow->packet_counter < 3 &&
			!flow->protocol_id_already_guessed) {
		prefix_t ipx;
		patricia_node_t *node;
		r_proto = NDPI_PROTOCOL_UNKNOWN;
		fill_prefix_any(&ipx,&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3,AF_INET);

		spin_lock_bh (&n->ipq_lock);
		node = ndpi_patricia_search_best(n->ndpi_struct->protocols_ptree,&ipx);
		if(node) {
		    if(protocol == IPPROTO_UDP)
			r_proto = ndpi_check_ipport(node,up_port,0);
		    if(protocol == IPPROTO_TCP)
			r_proto = ndpi_check_ipport(node,up_port,1);

		    if(r_proto != NDPI_PROTOCOL_UNKNOWN)
			proto.protocol = r_proto;
		}
		spin_unlock_bh (&n->ipq_lock);
		if(r_proto != NDPI_PROTOCOL_UNKNOWN) {
			fill_prefix_any(&ipx,&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3,AF_INET);
			spin_lock_bh (&n->ipq_lock);
			node = ndpi_patricia_search_best(n->ndpi_struct->protocols_ptree,&ipx);
			if(node) {
			    if(protocol == IPPROTO_UDP)
				r_proto = ndpi_check_ipport(node,low_port,0);
			    if(protocol == IPPROTO_TCP)
				r_proto = ndpi_check_ipport(node,low_port,1);
			    if(r_proto != NDPI_PROTOCOL_UNKNOWN)
				proto.protocol = r_proto;
			}
			spin_unlock_bh (&n->ipq_lock);
		}
		if(proto.protocol != NDPI_PROTOCOL_UNKNOWN)
			flow->protocol_id_already_guessed = 1;
	    }
	    if(proto.protocol == NDPI_PROTOCOL_UNKNOWN) {
		if(low_ip > up_ip) { tmp_ip = low_ip; low_ip=up_ip; up_ip = tmp_ip; }
		if(low_port > up_port) { tmp_port = low_port; low_port=up_port; up_port = tmp_port; }
		proto = ndpi_guess_undetected_protocol (
				n->ndpi_struct,protocol,low_ip,low_port,up_ip,up_port);
	    }
	} else {
		add_stat(flow->packet.parsed_lines);
	}

	r_proto = proto.protocol;
	if(r_proto == NDPI_PROTOCOL_UNKNOWN) r_proto = proto.master_protocol;
	if(r_proto != NDPI_PROTOCOL_UNKNOWN && r_proto > NDPI_LAST_IMPLEMENTED_PROTOCOL) {
		r_proto = NDPI_PROTOCOL_UNKNOWN;
	} else {
		ct_ndpi->proto = proto;
	}

	return r_proto;
}
static inline int can_handle(const struct sk_buff *skb,u8 *l4_proto)
{
	const struct iphdr *iph;
	u32 l4_len;
	u8 proto;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	const struct ipv6hdr *ip6h;

	ip6h = ipv6_hdr(skb);
	if(ip6h->version == 6) {
		COUNTER(ndpi_pa);
		*l4_proto = ip6h->nexthdr;
		// FIXME!
		return 1;
	}
#endif
	iph = ip_hdr(skb);
        if(!iph) { /* not IP */
		COUNTER(ndpi_pb); return 0;
	}
	if(iph->version != 4) {
		COUNTER(ndpi_pb); return 0;
	}
	*l4_proto = proto = iph->protocol;
	COUNTER(ndpi_p0);

	if(ntohs(iph->frag_off) & 0x3fff) {
		COUNTER(ndpi_p1); return 0;
	}
	if(skb->len <= (iph->ihl << 2)) {
		COUNTER(ndpi_p1); return 0; 
	}

	l4_len = skb->len - (iph->ihl << 2);
        if(proto == IPPROTO_TCP) {
		if(l4_len < sizeof(struct tcphdr)) {
			COUNTER(ndpi_p2); return 0;
		}
		return 1;
	}
        if(proto == IPPROTO_UDP) {
		if(l4_len < sizeof(struct udphdr)) {
			COUNTER(ndpi_p2); return 0;
		}
		return 1;
	}
	COUNTER(ndpi_p7);
	return 1;
}

#define NDPI_ID 0x44504900ul

static bool
ndpi_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	u32 r_proto;
	ndpi_protocol proto = NDPI_PROTOCOL_NULL;
	u64 time;
	const struct xt_ndpi_mtinfo *info = par->matchinfo;

	enum ip_conntrack_info ctinfo;
	struct nf_conn * ct;
	struct timeval tv;
	struct sk_buff *linearized_skb = NULL;
	const struct sk_buff *skb_use = NULL;
	struct nf_ct_ext_ndpi *ct_ndpi = NULL;
	struct ndpi_cb *c_proto;
	u8 l4_proto=0;
	char ct_buf[128];

	proto.protocol = NDPI_PROCESS_ERROR;

	c_proto = (void *)&skb->cb[sizeof(skb->cb)-sizeof(struct ndpi_cb)];

    do {
	if(c_proto->data[0] == NDPI_ID &&
	   c_proto->data[1] == NDPI_PROCESS_ERROR) {
		break;
	}
	if(!can_handle(skb,&l4_proto)) {
		proto.protocol = NDPI_PROTOCOL_UNKNOWN;
		break;
	}
	if( skb->len > ndpi_mtu && skb_is_nonlinear(skb) ) {
		COUNTER(ndpi_jumbo);
		break;
	}

	COUNTER(ndpi_pk);

	ct = nf_ct_get (skb, &ctinfo);
	if (ct == NULL) {
		COUNTER(ndpi_p31);
		break;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	if (nf_ct_is_untracked(ct))
#else
	if(ctinfo == IP_CT_UNTRACKED)	
#endif
	{
		COUNTER(ndpi_p31);
		break;
	}

#ifdef NF_CT_CUSTOM
	ct_ndpi = nf_ct_ext_find_ndpi(ct);
	if(!ct_ndpi) {
		if(nf_ct_is_confirmed(ct)) {
			COUNTER(ndpi_p31);
			break;
		}
		ct_ndpi = nf_ct_ext_add_ndpi(ct);
		if(ndpi_log_debug > 2)
			printk("Create  ct_ndpi %p ct %p %s\n",
					(void *)ct_ndpi, (void *)ct,
					ct_info(ct,ct_buf,sizeof(ct_buf)));
		if(ct_ndpi) {
			ndpi_init_ct_struct(ct_ndpi,l4_proto);
		} else {
			COUNTER(ndpi_p34);
			break;
		}
	} else
	    if(ndpi_log_debug > 2)
		printk("Reuse   ct_ndpi %p ct %p %s\n",
				(void *)ct_ndpi, (void *)ct,
				ct_info(ct,ct_buf,sizeof(ct_buf)));
#else
	{
	    struct nf_ct_ext_labels *ct_label = nf_ct_ext_find_label(ct);
	    if(ct_label) {
		if(!ct_label->magic) {
			ct_ndpi = (struct nf_ct_ext_ndpi *)malloc_wrapper(sizeof(struct nf_ct_ext_ndpi));
			if(ct_ndpi) {
				ct_label->magic = MAGIC_CT;
				ct_label->ndpi_ext = ct_ndpi;
				ndpi_init_ct_struct(ct_ndpi,l4_proto);
				if(ndpi_log_debug > 2)
					printk("Create  ct_ndpi %p ct %p %s\n",
						(void *)ct_ndpi, (void *)ct, ct_info(ct,ct_buf,sizeof(ct_buf)));
			}
		} else {
			if(ct_label->magic == MAGIC_CT) {
				ct_ndpi = ct_label->ndpi_ext;
				if(ndpi_log_debug > 2)
					printk("Reuse   ct_ndpi %p ct %p %s\n",
						(void *)ct_ndpi, (void *)ct, ct_info(ct,ct_buf,sizeof(ct_buf)));
			  } else
				COUNTER(ndpi_p34);
		}
	    } else 
		COUNTER(ndpi_p31);
	}
#endif
	if(!ct_ndpi)
		break;

	proto.protocol = NDPI_PROTOCOL_UNKNOWN;
	if(ndpi_log_debug > 3)
		packet_trace(skb,ct,"Start      ");

	spin_lock_bh (&ct_ndpi->lock);

	if( c_proto->data[0] == NDPI_ID ) {
	    if(c_proto->last_ct == ct) {
		proto = ct_ndpi->proto;
		spin_unlock_bh (&ct_ndpi->lock);
		COUNTER(ndpi_pi);
		if(ndpi_log_debug > 1)
		    packet_trace(skb,ct,"cache      ");
		break;
	    }
	    if(c_proto->last_ct != ct)
		    	COUNTER(ndpi_pi3);
	} else
		COUNTER(ndpi_pi4);

	/* don't pass icmp for TCP/UDP to ndpi_process_packet()  */
	if(l4_proto == IPPROTO_ICMP && ct_ndpi->l4_proto != IPPROTO_ICMP) {
		proto.master_protocol = NDPI_PROTOCOL_IP_ICMP;
		proto.protocol = NDPI_PROTOCOL_IP_ICMP;
		spin_unlock_bh (&ct_ndpi->lock);
		COUNTER(ndpi_pj);
		ndpi_pjc += skb->len;
		break;
	}
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	if(l4_proto == IPPROTO_ICMPV6 && ct_ndpi->l4_proto != IPPROTO_ICMPV6) {
		proto.master_protocol = NDPI_PROTOCOL_IP_ICMPV6;
		proto.protocol = NDPI_PROTOCOL_IP_ICMPV6;
		spin_unlock_bh (&ct_ndpi->lock);
		COUNTER(ndpi_pj);
		ndpi_pjc += skb->len;
		break;
	}
#endif
	if(ct_ndpi->proto.protocol == NDPI_PROTOCOL_UNKNOWN ||
	    ct_ndpi->flow) {
		struct ndpi_net *n;

		if (skb_is_nonlinear(skb)) {
			linearized_skb = skb_copy(skb, GFP_ATOMIC);
			if (linearized_skb == NULL) {
				spin_unlock_bh (&ct_ndpi->lock);
				COUNTER(ndpi_falloc);
				proto.protocol = NDPI_PROCESS_ERROR;
				break;
			}
			skb_use = linearized_skb;
			ndpi_nskb += 1;
		} else {
			skb_use = skb;
			ndpi_lskb += 1;
		}

		do_gettimeofday(&tv);

		time = ((uint64_t) tv.tv_sec) * detection_tick_resolution +
			tv.tv_usec / (1000000 / detection_tick_resolution);

		n = ndpi_pernet(nf_ct_net(ct));
		r_proto = ndpi_process_packet(n, ct,
				ct_ndpi, time, skb_use,
				CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL);

		c_proto->data[0] = NDPI_ID;
		c_proto->data[1] = r_proto;
		c_proto->last_ct = ct;
		COUNTER(ndpi_pd);

		if(r_proto != NDPI_PROTOCOL_UNKNOWN) {
		   if(r_proto != NDPI_PROCESS_ERROR) {
			proto = ct_ndpi->proto;
			c_proto->data[1] = *(uint32_t *)&proto;
			if(proto.protocol != NDPI_PROTOCOL_UNKNOWN)
				atomic_inc(&n->protocols_cnt[proto.protocol]);
			if(proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
				atomic_inc(&n->protocols_cnt[proto.master_protocol]);
		   } else {
			// special case for errors
			COUNTER(ndpi_pe);
			c_proto->data[1] = NDPI_PROCESS_ERROR;
			proto.protocol = r_proto;
			proto.master_protocol = NDPI_PROTOCOL_UNKNOWN;
			if(ct_ndpi->proto.protocol == NDPI_PROTOCOL_UNKNOWN) {
				ct_ndpi->proto.protocol = r_proto;
			}
		   }
		} else { // unknown
			if(ct_ndpi->proto.protocol != NDPI_PROTOCOL_UNKNOWN &&
			   ct_ndpi->flow->no_cache_protocol) { // restore proto
				proto = ct_ndpi->proto;
				c_proto->data[1] = *(uint32_t *)&proto;
			}
		}
		spin_unlock_bh (&ct_ndpi->lock);

		if(linearized_skb != NULL)
			kfree_skb(linearized_skb);
	}
    } while(0);

    if (info->error)
    	return (proto.protocol == NDPI_PROCESS_ERROR) ^ (info->invert != 0);
    if (info->have_master)
    	return (proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) ^ (info->invert != 0);
    
    if (info->m_proto && !info->p_proto)
    	return (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,proto.master_protocol) != 0 )  ^ (info->invert != 0);
    if (!info->m_proto && info->p_proto)
    	return (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,proto.protocol) != 0 )  ^ (info->invert != 0);

    if (proto.protocol != NDPI_PROTOCOL_UNKNOWN) {
		r_proto = NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,proto.protocol) != 0;
		if(proto.master_protocol !=  NDPI_PROTOCOL_UNKNOWN)
			r_proto |= NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,proto.master_protocol) != 0;

	    	return r_proto ^ (info->invert != 0);
    }
    return (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,proto.master_protocol) != 0 )  ^ (info->invert != 0);
	
}


static int
ndpi_mt_check(const struct xt_mtchk_param *par)
{
const struct xt_ndpi_mtinfo *info = par->matchinfo;

	if (!info->error &&  !info->have_master &&
	     NDPI_BITMASK_IS_ZERO(info->flags)) {
		pr_info("No selected protocols.\n");
		return -EINVAL;
	}

	ndpi_enable_protocols (ndpi_pernet(par->net));
	return 0;
}

static void 
ndpi_mt_destroy (const struct xt_mtdtor_param *par)
{
}

#ifdef NF_CT_CUSTOM
char *ndpi_proto_to_str(char *buf,size_t size,ndpi_protocol *p)
{
buf[0] = '\0';
if(p->protocol && p->protocol <= NDPI_LAST_IMPLEMENTED_PROTOCOL)
	strncpy(buf,prot_short_str[p->protocol],size);
if(p->master_protocol && p->master_protocol <= NDPI_LAST_IMPLEMENTED_PROTOCOL) {
	strncat(buf,",",size);
	strncat(buf,prot_short_str[p->master_protocol],size);
}
return buf;
}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
static unsigned int seq_print_ndpi(struct seq_file *s,
					  const struct nf_conn *ct,
					  int dir)
{

       struct nf_ct_ext_ndpi *ct_ndpi;
       char res_str[64];
       if(dir != IP_CT_DIR_REPLY) return 0;

       ct_ndpi = nf_ct_ext_find_ndpi(ct);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
       if(ct_ndpi && (ct_ndpi->proto.protocol || ct_ndpi->proto.master_protocol))
	       seq_printf(s,"ndpi=%s ",ndpi_proto_to_str(res_str,sizeof(res_str),&ct_ndpi->proto));
       return 0;
#else
       return ct_ndpi && (ct_ndpi->proto.protocol || ct_ndpi->proto.master_protocol) ?
	       seq_printf(s,"ndpi=%s ",ndpi_proto_to_str(res_str,sizeof(res_str),&ct_ndpi->proto)): 0;
#endif
}
#endif
#endif

static void ndpi_proto_markmask(struct ndpi_net *n, u_int32_t *var,
		ndpi_protocol *proto, int mode)
{
    if(mode == 1) {
	if(proto->master_protocol <= NDPI_LAST_IMPLEMENTED_PROTOCOL) {
		*var &= ~n->mark[proto->master_protocol].mask;
		*var |=  n->mark[proto->master_protocol].mark;
	}
	return;
    }
    if(mode == 2) {
	if(proto->protocol <= NDPI_LAST_IMPLEMENTED_PROTOCOL) {
		*var &= ~n->mark[proto->protocol].mask;
		*var |=  n->mark[proto->protocol].mark;
	}
	return;
    }
    if(proto->master_protocol != NDPI_PROTOCOL_UNKNOWN) {
	if(proto->master_protocol <= NDPI_LAST_IMPLEMENTED_PROTOCOL) {
		*var &= ~n->mark[proto->master_protocol].mask;
		*var |=  n->mark[proto->master_protocol].mark;
	}
	if(proto->protocol != NDPI_PROTOCOL_UNKNOWN) {
	    if(proto->protocol <= NDPI_LAST_IMPLEMENTED_PROTOCOL) {
		*var &= ~n->mark[proto->protocol].mask;
		*var |=  n->mark[proto->protocol].mark;
	    }
	}
    } else {
	if(proto->protocol <= NDPI_LAST_IMPLEMENTED_PROTOCOL) {
		*var &= ~n->mark[proto->protocol].mask;
		*var |=  n->mark[proto->protocol].mark;
	}
    }
}

static unsigned int
ndpi_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_ndpi_tginfo *info = par->targinfo;
	ndpi_protocol proto = NDPI_PROTOCOL_NULL;
	struct ndpi_net *n = ndpi_pernet(dev_net(skb->dev ? : skb_dst(skb)->dev));
	int mode = 0;

	if(info->p_proto_id || info->m_proto_id || info->any_proto_id) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn * ct;
		struct nf_ct_ext_ndpi *ct_ndpi;

		ct = nf_ct_get (skb, &ctinfo);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
		if (ct && !nf_ct_is_untracked(ct))
#else
		if(ctinfo != IP_CT_UNTRACKED)	
#endif
		{
		    ct_ndpi = nf_ct_ext_find_ndpi(ct);
		    if(ct_ndpi) {
			spin_lock_bh (&ct_ndpi->lock);
			proto = ct_ndpi->proto;
			spin_unlock_bh (&ct_ndpi->lock);
		    }
		}
		if(info->m_proto_id) mode |= 1;
		if(info->p_proto_id) mode |= 2;
		if(info->any_proto_id) mode |= 3;
	}

	if(info->t_mark) {
	        skb->mark = (skb->mark & ~info->mask) | info->mark;
		if(mode)
			ndpi_proto_markmask(n,&skb->mark,&proto,mode);
	}
	if(info->t_clsf) {
	        skb->priority = (skb->priority & ~info->mask) | info->mark;
		if(mode)
			ndpi_proto_markmask(n,&skb->priority,&proto,mode);
	}
        return info->t_accept ? NF_ACCEPT : XT_CONTINUE;
}

static int
ndpi_tg_check(const struct xt_tgchk_param *par)
{
        ndpi_enable_protocols (ndpi_pernet(par->net));
	return nf_ct_l3proto_try_module_get (par->family);
}

static void 
ndpi_tg_destroy (const struct xt_tgdtor_param *par)
{
	nf_ct_l3proto_module_put (par->family);
}


static struct xt_match
ndpi_mt_reg __read_mostly = {
	.name = "ndpi",
	.revision = 0,
#ifdef NDPI_DETECTION_SUPPORT_IPV6
        .family = NFPROTO_UNSPEC,
#else
	.family = NFPROTO_IPV4,
#endif
	.match = ndpi_mt,
	.checkentry = ndpi_mt_check,
	.destroy = ndpi_mt_destroy,
	.matchsize = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
	.me = THIS_MODULE,
};

static struct xt_target ndpi_tg_reg __read_mostly = {
        .name           = "NDPI",
        .revision       = 0,
#ifdef NDPI_DETECTION_SUPPORT_IPV6
        .family         = NFPROTO_UNSPEC,
#else
	.family		= NFPROTO_IPV4,
#endif
        .target         = ndpi_tg,
	.checkentry	= ndpi_tg_check,
	.destroy	= ndpi_tg_destroy,
        .targetsize     = sizeof(struct xt_ndpi_tginfo),
        .me             = THIS_MODULE,
};

static void bt_port_gc(unsigned long data) {
        struct ndpi_net *n = (struct ndpi_net *)data;
        struct ndpi_detection_module_struct *ndpi_struct = n->ndpi_struct;
	struct hash_ip4p_table *ht = ndpi_struct->bt_ht;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	struct hash_ip4p_table *ht6 = ndpi_struct->bt6_ht;
#endif
	struct timespec tm;
	int i;

	if(!ht
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		&& !ht6
#endif
		)  return;

	getnstimeofday(&tm);
	spin_lock(&ht->lock);
	/* full period 64 seconds */
	for(i=0; i < ht->size/128;i++) {
		if(n->gc_index < 0 ) n->gc_index = 0;
		if(n->gc_index >= ht->size-1) n->gc_index = 0;

		if(ht && ht->tbl[n->gc_index].len)
			n->gc_count += ndpi_bittorrent_gc(ht,n->gc_index,tm.tv_sec);
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		if(ht6) {
		   if(ht6->tbl[n->gc_index].len)
			n->gc_count += ndpi_bittorrent_gc(ht6,n->gc_index,tm.tv_sec);
		}
#endif
		n->gc_index++;
	}
	spin_unlock(&ht->lock);
	
	ndpi_bt_gc = n->gc_count;

	n->gc.expires = jiffies + HZ/2;
	add_timer(&n->gc);
}

static int inet_ntop_port(int family,void *ip, u_int16_t port, char *lbuf, size_t bufsize) {
u_int8_t *ipp = (u_int8_t *)ip;
u_int16_t *ip6p = (u_int16_t *)ip;
return  family == AF_INET6 ?
		snprintf(lbuf,bufsize-1, "%x:%x:%x:%x:%x:%x:%x:%x.%d",
			htons(ip6p[0]),htons(ip6p[1]),htons(ip6p[2]),htons(ip6p[3]),
			htons(ip6p[4]),htons(ip6p[5]),htons(ip6p[6]),htons(ip6p[7]),
			htons(port))
	      :	snprintf(lbuf,bufsize-1, "%d.%d.%d.%d:%d",
			ipp[0],ipp[1],ipp[2],ipp[3],htons(port));
}

static int inet_ntop(int family,void *ip, char *lbuf, size_t bufsize) {
u_int8_t *ipp = (u_int8_t *)ip;
u_int16_t *ip6p = (u_int16_t *)ip;
return  family == AF_INET6 ?
		snprintf(lbuf,bufsize-1, "%x:%x:%x:%x:%x:%x:%x:%x",
			htons(ip6p[0]),htons(ip6p[1]),htons(ip6p[2]),htons(ip6p[3]),
			htons(ip6p[4]),htons(ip6p[5]),htons(ip6p[6]),htons(ip6p[7]))
	     :	snprintf(lbuf,bufsize-1, "%d.%d.%d.%d",
			ipp[0],ipp[1],ipp[2],ipp[3]);
}

static ssize_t _ninfo_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos,int family)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
        struct ndpi_detection_module_struct *ndpi_struct = n->ndpi_struct;
	struct hash_ip4p_table *ht,*ht4 = ndpi_struct->bt_ht;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	struct hash_ip4p_table *ht6 = ndpi_struct->bt6_ht;
#endif
	char lbuf[128];
	struct hash_ip4p *t;
	size_t p;
	int l;
	ht = 
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		family == AF_INET6 ? ht6:
#endif
		ht4;
	if(!ht) {
	    if(!*ppos) {
	        l =  snprintf(lbuf,sizeof(lbuf)-1, "hash disabled\n");
		if (!(access_ok(VERIFY_WRITE, buf, l) &&
				! __copy_to_user(buf, lbuf, l))) return -EFAULT;
		(*ppos)++;
		return l;
	    }
	    return 0;
	}
	if(n->n_hash < 0 || n->n_hash >= ht->size-1) {
	    int tmin,tmax,i;

	    if(!*ppos) {
		tmin = 0x7fffffff;
		tmax = 0;
		t = &ht->tbl[0];

		for(i = ht->size-1; i >= 0 ;i--,t++) {
			if(t->len > 0 && t->len < tmin) tmin = t->len;
			if(t->len > tmax) tmax = t->len;
		}
		if(!atomic_read(&ht->count)) tmin = 0;
	        l =  snprintf(lbuf,sizeof(lbuf)-1,
			"hash_size %lu hash timeout %lus count %u min %d max %d gc %d\n",
				bt_hash_size*1024,bt_hash_tmo,
				atomic_read(&ht->count),tmin,tmax,n->gc_count	);

		if (!(access_ok(VERIFY_WRITE, buf, l) &&
				! __copy_to_user(buf, lbuf, l))) return -EFAULT;
		(*ppos)++;
		return l;
	    }
	    /* ppos > 0 */
#define BSS1 144
#define BSS2 12
	    if(*ppos * BSS1 >= bt_hash_size*1024) return 0;

	    t = &ht->tbl[(*ppos-1)*BSS1];
	    p=0;
	    for(i=0; i < BSS1;i++,t++) {
		if(!(i % BSS2)) {
		        l = snprintf(lbuf,sizeof(lbuf)-1, "%d:\t",(int)(i+(*ppos-1)*BSS1));
			if (!(access_ok(VERIFY_WRITE, buf+p, l) && !__copy_to_user(buf+p, lbuf, l)))
				return -EFAULT;
			p += l;
		}
	        l = snprintf(lbuf,sizeof(lbuf)-1, "%5zu%c",
				t->len, (i % BSS2) == (BSS2-1) ? '\n':' ');
		
		if (!(access_ok(VERIFY_WRITE, buf+p, l) &&
				!__copy_to_user(buf+p, lbuf, l)))
			return -EFAULT;
		p += l;
	    }
	    (*ppos)++;
	    return p;
	}
	t = &ht->tbl[n->n_hash];
	if(!*ppos) {
	        l =  snprintf(lbuf,sizeof(lbuf)-1, "index %d len %zu\n",
				n->n_hash,t->len);
		if (!(access_ok(VERIFY_WRITE, buf, l) &&
				!__copy_to_user(buf, lbuf, l))) return -EFAULT;
		(*ppos)++;
		return l;
	}
	if(*ppos > 1) return 0;
	p = 0;
	spin_lock(&t->lock);
	do {
		struct hash_ip4p_node *x = t->top;
	 	struct timespec tm;

	        getnstimeofday(&tm);
		while(x && p < count - 128) {
		        l =  inet_ntop_port(family,&x->ip,x->port,lbuf,sizeof(lbuf)-2);
			l += snprintf(&lbuf[l],sizeof(lbuf)-l-1, " %d %x %u\n",
				(int)(tm.tv_sec - x->lchg),x->flag,x->count);

			if (!(access_ok(VERIFY_WRITE, buf+p, l) &&
				!__copy_to_user(buf+p, lbuf, l))) return -EFAULT;
			p += l;
			x = x->next;
		}
	} while(0);
	spin_unlock(&t->lock);
	(*ppos)++;
	return p;
}

static int ninfo_proc_open(struct inode *inode, struct file *file)
{
        return 0;
}
static ssize_t ninfo_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
return _ninfo_proc_read(file,buf,count,ppos,AF_INET);
}

#ifdef NDPI_DETECTION_SUPPORT_IPV6
static ssize_t ninfo6_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
return _ninfo_proc_read(file,buf,count,ppos,AF_INET6);
}
#endif

static ssize_t
ninfo_proc_write(struct file *file, const char __user *buffer,
                     size_t length, loff_t *loff)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
	char buf[32];
	int idx;

        if (length > 0) {
		memset(buf,0,sizeof(buf));
		if (!(access_ok(VERIFY_READ, buffer, length) && 
			!__copy_from_user(&buf[0], buffer, min(length,sizeof(buf)-1))))
			        return -EFAULT;
		if(sscanf(buf,"%d",&idx) != 1) return -EINVAL;
		n->n_hash = idx;
        }
        return length;
}

#ifdef BT_ANNOUNCE
static ssize_t nann_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
        struct ndpi_detection_module_struct *ndpi_struct = n->ndpi_struct;
	struct bt_announce *b = ndpi_struct->bt_ann;
	int  bt_len = ndpi_struct->bt_ann_len;
	char lbuf[512],ipbuf[64];
	int i,l,p;

	for(i = 0,p = 0; i < bt_len; i++,b++) {
		if(!b->time) break;

		if(i < *ppos ) continue;
		if(!b->ip[0] && !b->ip[1] && b->ip[2] == 0xfffffffful)
			inet_ntop_port(AF_INET,&b->ip[3],b->port,ipbuf,sizeof(ipbuf));
		    else
			inet_ntop_port(AF_INET6,&b->ip,b->port,ipbuf,sizeof(ipbuf));
	        l =  snprintf(lbuf,sizeof(lbuf)-1, "%08x%08x%08x%08x%08x %s %u '%.*s'\n",
				htonl(b->hash[0]),htonl(b->hash[1]),
				htonl(b->hash[2]),htonl(b->hash[3]),htonl(b->hash[4]),
				ipbuf,b->time,b->name_len,b->name);

		if(count < l) break;

		if (!(access_ok(VERIFY_WRITE, buf+p, l) &&
				!__copy_to_user(buf+p, lbuf, l))) return -EFAULT;
		p += l;
		count -= l;
		(*ppos)++;
	}
	return p;
}
#endif


/*************************** ip_def **************************/

static uint16_t ndpi_check_ipport(patricia_node_t *node,uint16_t port,int l4) {
struct ndpi_port_def *pd;
if(!node) return NDPI_PROTOCOL_UNKNOWN;
pd = node->data;
if(!pd) return NDPI_PROTOCOL_UNKNOWN;
if(pd->count[l4]) {
	int start,end,i;
	ndpi_port_range_t *pt;

	start = !l4 ? 0:pd->count[0];
	end = start + pd->count[l4];

	if(port >= pd->p[start].start &&
	   port <= pd->p[end-1].end) {
		i = start + ((end-start) >> 1);
		do {
			pt = &pd->p[i];
			if(pt->start <= port && port <= pt->end) return pt->proto;
			if(port < pt->start) {
			    end = i;
			} else {
			    start = i+1;
			}
			i = start + ((end-start) >> 1);
		} while(start < end);
	}
}
/* FIXME */
//return node->value.user_value;
return NDPI_PROTOCOL_UNKNOWN;
}

static int ndpi_print_port_range(ndpi_port_range_t *pt,
		int count,char *buf,size_t bufsize) {
 int l = 0;
	for(; count > 0; count--,pt++) {
		if(l && l < bufsize) buf[l++] = ' ';
		l += snprintf(&buf[l],bufsize - l,"%s",
			  pt->l4_proto ? "tcp":"udp");
		if(pt->start == pt->end)
		  l += snprintf(&buf[l],bufsize - l,":%d",pt->start);
		else
		  l += snprintf(&buf[l],bufsize - l,":%d-%d",pt->start,pt->end);

		l += snprintf(&buf[l],bufsize - l,":%s",
			  pt->proto > NDPI_LAST_IMPLEMENTED_PROTOCOL ?
				"unknown":prot_short_str[pt->proto]);
		if(l == bufsize) break;
	}
	return l;
}

/*
 * [-]prefix ([[(tcp|udp|any):]port[-port]:]protocol)+
 */

static int parse_n_proto(char *pr,ndpi_port_range_t *np)
{
int i;
if(!*pr) return 1;

if(!strcmp(pr,"any")) {
	np->proto = NDPI_LAST_IMPLEMENTED_PROTOCOL+1;
	return 0;
}
for(i=1; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
	if(prot_short_str[i] && !strcmp(pr,prot_short_str[i])) {
		DP("parse_n_proto(%s)=%x\n",pr,i);
		np->proto =i;
		return 0;
	}
}
return 1;
}

static int parse_l4_proto(char *pr,ndpi_port_range_t *np)
{
if(!*pr) return 1;

if(!strcmp(pr,"any")) {
	np->l4_proto = 2; return 0;
}
if(!strcmp(pr,"tcp")) {
	np->l4_proto = 1; return 0;
}
if(!strcmp(pr,"udp")) {
	np->l4_proto = 0; return 0;
}
return 1;
}

static int parse_port_range(char *pr,ndpi_port_range_t *np)
{
    char *d;
    uint32_t v;
    
    if(!*pr) return 1;

    if(!strcmp(pr,"any")) {
	np->start = 0;
	np->end = 0;
	return 0;
    }
    d = strchr(pr,'-');
    if(d) *d++ = '\0';
    
    if(kstrtou32(pr,10,&v)) return 1;
    if(v > 0xffff) return 1;

    np->start = v;

    if(d) {
    	if(kstrtou32(d,10,&v)) return 1;
	if(v > 0xffff) return 1;
	np->end = v;
    } else {
    	np->end = v;
    }
    if(np->start > np->end) {
	    v = np->start;
	    np->start = np->end;
	    np->end = v;
    }
    if(d) *--d = '-';

    return 0;
}

/**************************************************************/
struct ndpi_port_def *ndpi_port_range_replace(
		struct ndpi_port_def *pd,
		int start, int end,
		ndpi_port_range_t *np,
		int count,int proto)
{
struct ndpi_port_def *pd1;

DBGDATA(char dbuf[256])

#ifdef NDPI_IPPORT_DEBUG
ndpi_print_port_range(pd->p,pd->count[0]+pd->count[1],dbuf,sizeof(dbuf));
DP("%s: old %d,%d %s\n",__func__,pd->count[0],pd->count[1],dbuf);
ndpi_print_port_range(np,count,dbuf,sizeof(dbuf));
DP("%s: on %d,%d,%d,%d %s\n",__func__,start,end,count,proto,dbuf);
#endif

if( (end-start) == count) {
	if(count) {
	    memcpy(&pd->p[start],np,count*sizeof(ndpi_port_range_t));
	    DP("%s: replaced!\n",__func__);
	}
	return pd;
}

pd1 = ndpi_malloc( sizeof(struct ndpi_port_def) + 
		   sizeof(ndpi_port_range_t) * 
		   (count + pd->count[1-proto]));
if(!pd1) return pd;

memcpy(pd1,pd,sizeof(struct ndpi_port_def));
if(!proto) { // udp
	if(count) 
		memcpy( &pd1->p[0],np,count*sizeof(ndpi_port_range_t));
	if(pd->count[1])
		memcpy( &pd1->p[pd->count[0]], &pd->p[pd->count[0]],
			pd->count[1]*sizeof(ndpi_port_range_t));
	pd1->count[0] = count;
} else { // tcp
	if(pd->count[0])
		memcpy( &pd1->p[0], &pd->p[0],
			pd->count[0]*sizeof(ndpi_port_range_t));
	if(count)
		memcpy( &pd1->p[pd->count[0]], np,
			count*sizeof(ndpi_port_range_t));
	pd1->count[1] = count;
}

#ifdef NDPI_IPPORT_DEBUG
ndpi_print_port_range(pd1->p,pd1->count[0]+pd1->count[1],dbuf,sizeof(dbuf));
printk("%s: res %d,%d %s\n",__func__,pd1->count[0],pd1->count[1],dbuf);
#endif

ndpi_free(pd);
return pd1;
}

struct ndpi_port_def *ndpi_port_range_update(
		struct ndpi_port_def *pd,
		ndpi_port_range_t *np,
		int proto,int op)
{
ndpi_port_range_t *tp,*tmp;
int i,n,k;
int start,end;
if(!proto) {
	start = 0;
	end   = pd->count[0];
} else {
	start = pd->count[0];
	end   = start + pd->count[1];
}
n = end-start;
DP("%s: %s:%d-%d:%d %d %d %d %s\n",__func__,
	np->l4_proto ? (np->l4_proto == 1 ? "tcp":"any"):"udp",
	np->start,np->end,np->proto,start,end,proto,
	op ? "set":"del");

if(!n) {
	if(!op) return pd;
	return ndpi_port_range_replace(pd,start,end,np,1,proto); // create 1 range
}

tmp = ndpi_malloc(sizeof(ndpi_port_range_t)*(n+2));
if(!tmp) return pd;
memset((char *)tmp,0,sizeof(ndpi_port_range_t)*(n+2));

i = start;
tp = &pd->p[i];
k = 0;

#ifdef NDPI_IPPORT_DEBUG
#define DD1 printk("%s: k=%d tmp %d-%d i=%d tp %d-%d np %d-%d \n", \
		__func__,k,tmp[k].start,tmp[k].end,i,tp->start,tp->end,np->start,np->end);
#else
#define DD1
#endif
for(;i < end && np->start > tp->end; tp++,i++) {
	DD1
	tmp[k++] = *tp;
}
DD1
if(i < end ) {
	DD1;
	if(np->start > tp->start && np->start < tp->end) {
	    tmp[k] = *tp;
	    tmp[k].end = np->start-1;
	    k++;
	    DP("%s: P0 k %d\n",__func__,k);
	}
	tmp[k] = *np;
	DD1;
      v0:
	if(np->end < tp->start) {
	    // insert before old ranges
	    DP("%s: P1\n",__func__);
	    goto copy_tail;
	}
	if(np->end < tp->end) {
	    k++;
	    tmp[k] = *tp++; i++;
	    tmp[k].start = np->end+1;
	    DP("%s: P2\n",__func__);
	    goto copy_tail;
	}
	if(np->end == tp->end) { // override first old range
	    tp++; i++;
	    DP("%s: P3\n",__func__);
	    goto copy_tail;
	}
	// np->end > tp->end
	for(; i < end; i++,tp++) {
	    if(np->end > tp->end) continue;
	    goto v0;
	}
	k++;
	// override all old ranges!
	goto check_eq_proto;
} else {
	// append new range
	tmp[k++] = *np;
	DP("%s: P4 k=%d\n",__func__,k);
	goto check_eq_proto; // OK
}

copy_tail:
    k++;
    for(; i < end; i++,tp++) tmp[k++] = *tp;

// k - new length of range
check_eq_proto:

#ifdef NDPI_IPPORT_DEBUG
{
char dbuf[128];
ndpi_print_port_range(tmp,k,dbuf,sizeof(dbuf));
printk("%s: k=%d: %s\n",__func__,k,dbuf);
}
#endif

if(k <= 1) {
    if(!op) k = 0;
} else {
    int l;
    if(!op) {
	for(l = 0 , i = 0; i < k; i++) {
	    if(tmp[i].start == np->start &&
		tmp[i].end   == np->end &&
		tmp[i].proto == np->proto) {
		continue;	
	    }
	    if(i != l) tmp[l++] = tmp[i];
	}
	k = l;
    }

    for(l = 0; l < k-1; ) {
	i = l+1;
	DP("l=%d %d-%d.%d i=%d %d-%d.%d n=%d\n",
		l,tmp[l].start,tmp[l].end,tmp[l].proto,
		i,tmp[i].start,tmp[i].end,tmp[i].proto,n);

	if(tmp[l].proto != tmp[i].proto ||
	   tmp[l].end+1 != tmp[i].start) {
	    l++;
	    continue;
	}
	tmp[l].end = tmp[i].end;
	for(;i < k-1; i++) tmp[i] = tmp[i+1];
	k--;
    }
    k = l+1;
}
DP("%s: k %d\n",__func__,k);

pd = ndpi_port_range_replace(pd,start,end,tmp,k,proto);
ndpi_free(tmp);
return pd;
}

void *ndpi_port_add_one_range(void *data, ndpi_port_range_t *np,int op)
{
struct ndpi_port_def *pd = data;
int i;
if(!pd) {
	if(!op) return data;

	i = np->l4_proto != 2 ? 1:2;
	pd = ndpi_malloc(sizeof(struct ndpi_port_def) + sizeof(ndpi_port_range_t)*i);
	if(!pd) return pd;

	pd->p[0] = *np;
	pd->count[0] = np->l4_proto != 1;
	pd->count[1] = np->l4_proto > 0;
	if(np->l4_proto == 2) {
		pd->p[1] = *np;
		pd->p[0].l4_proto = 0;
		pd->p[1].l4_proto = 1;
	}
	return pd;
}
if(np->l4_proto != 1) { // udp or any
	pd = ndpi_port_range_update(pd,np,0,op);
}
if(np->l4_proto > 0 ) { // tcp or any
	pd = ndpi_port_range_update(pd,np,1,op);
}
if(pd && (pd->count[0] + pd->count[1]) == 0) {
	ndpi_free(pd);
	pd = NULL;
}
return pd;
}

static int parse_ndpi_ipdef_cmd(struct ndpi_net *n, int f_op, prefix_t *prefix, char *arg) {
char *d1,*d2;
int f_op2=0;
int ret = 0;

ndpi_port_range_t np = { .start=0, .end=0, .l4_proto = 2, .proto = NDPI_PROTOCOL_UNKNOWN };
patricia_node_t *node;
patricia_tree_t *pt;

if(*arg == '-') {
	f_op2=1;
	arg++;
}
d1 = strchr(arg,':');
if(d1) *d1++='\0';
d2 = d1 ? strchr(d1,':'):NULL;
if(d2) *d2++='\0';
DP("%s(op=%d, %s %s %s)\n",__func__,f_op,arg,d1 ? d1: "(NULL)",d2 ? d2:"(NULL)");
if(d1) {
    if(d2) { // full spec
	if(parse_l4_proto(arg,&np)) return 1;
	if(parse_port_range(d1,&np)) return 1;
	if(parse_n_proto(d2,&np)) return 1;
	DP("%s:3 proto %d start %d end %d l4 %d\n",
			__func__,np.proto, np.start, np.end, np.l4_proto);
    } else {
	// port:protocol
	if(parse_port_range(arg,&np)) {
		//l4:proto
		if(parse_l4_proto(arg,&np)) return 1;
		np.end=65535;
	}
	if(parse_n_proto(d1,&np)) return 1;
	DP("%s:2 proto %d start %d end %d l4 %d\n",
			__func__,np.proto, np.start, np.end, np.l4_proto);
    }
} else {
	if(parse_n_proto(arg,&np)) return 1;
	DP("%s:1 proto %d\n",
			__func__,np.proto);
}

spin_lock_bh (&n->ipq_lock);

do {
pt = n->ndpi_struct->protocols_ptree;
node = ndpi_patricia_search_exact(pt,prefix);
DP(node ? "Found node\n":"Node not found\n");
if(f_op || f_op2) { // delete
	if(!node) break;
	// -xxxx any
	if(np.proto > NDPI_LAST_IMPLEMENTED_PROTOCOL && 
		np.l4_proto == 2 && !np.start && !np.end) {
		ndpi_patricia_remove(pt,node);
		break;
	}
	if(!np.start && !np.end) {
	    // -xxxx proto
	    if(node->value.user_value == np.proto) {
		if(!node->data) {
		    ndpi_patricia_remove(pt,node);
		} else {
		  node->value.user_value = 0;
		}
		break;
	    }
	}
	node->data = ndpi_port_add_one_range(node->data,&np,0);
	break;
}
// add or change
if(!node) {
	node = ndpi_patricia_lookup(pt, prefix);
	if(!node) {
		ret = 1; break;
	}
}

if(np.proto == NDPI_PROTOCOL_UNKNOWN || 
   np.proto > NDPI_LAST_IMPLEMENTED_PROTOCOL) {
	ret = 1; break;
}

if(!np.start && !np.end) {
	if(np.l4_proto == 2) {
	    // any:proto
	    node->value.user_value = np.proto;
	    break;
	}
	// (tcp|udp):any:proto
	np.start=1;
	np.end = 65535;
}
node->data = ndpi_port_add_one_range(node->data,&np,1);
} while (0);

spin_unlock_bh (&n->ipq_lock);

return ret;
}

#define SKIP_SPACE_C while(!!(c = *cmd) && (c == ' ' || c == '\t')) cmd++
#define SKIP_NONSPACE_C while(!!(c = *cmd) && (c != ' ') && (c != '\t')) cmd++

static int parse_ndpi_ipdef(struct ndpi_net *n,char *cmd) {
int f_op = 0; // 1 if delete
char *addr,c;
prefix_t *prefix;
int res = 0;

SKIP_SPACE_C;
if(*cmd == '#') return 0;
if(*cmd == '-') {
	f_op = 1; cmd++;
}
addr = cmd;
SKIP_NONSPACE_C;
if (*cmd) *cmd++ = 0;
SKIP_SPACE_C;
if(!*addr) return 1;
DP("prefix %s\n",addr);
prefix = ndpi_ascii2prefix(AF_INET,addr);
if(!prefix) return 1;

while(*cmd && !res) {
	char *t = cmd;
	SKIP_NONSPACE_C;
	if(*cmd) *cmd++ = 0;
	SKIP_SPACE_C;
	if(parse_ndpi_ipdef_cmd(n,f_op,prefix,t)) res=1;
}
ndpi_Deref_Prefix (prefix);
return res;
}

static ssize_t n_ipdef_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
	patricia_tree_t *pt;
	prefix_t *px;
	patricia_node_t *Xstack[PATRICIA_MAXBITS+1], **Xsp, *node;
	char lbuf[512];
	char ibuf[64];
	int i,l,p;

	i = 0; p = 0;
	pt = n->ndpi_struct->protocols_ptree;

	Xsp = &Xstack[0];
	node = pt->head;
	while (node) {
	    if (node->prefix) {

	      if(i >= *ppos ) {

		l = i ? 0: snprintf(lbuf,sizeof(lbuf),"#ip              proto\n");
		
		px = node->prefix;
		{
		int k;
		inet_ntop(px->family,(void *)&px->add,ibuf,sizeof(ibuf)-1);
		k = strlen(ibuf);
		if((px->family == AF_INET  && px->bitlen < 32 ) ||
		   (px->family == AF_INET6 && px->bitlen < 128 ))
			snprintf(&ibuf[k],sizeof(ibuf)-k,"/%d",px->bitlen);
		}
		if(node->value.user_value != NDPI_PROTOCOL_UNKNOWN)
		    l += snprintf(&lbuf[l],sizeof(lbuf)-l,"%-16s %s\n",ibuf,
			node->value.user_value > NDPI_LAST_IMPLEMENTED_PROTOCOL ?
				"unknown":prot_short_str[node->value.user_value]);
		if(node->data) {
			struct ndpi_port_def *pd = node->data;
			ndpi_port_range_t *pt = pd->p;
			if(pd->count[0]+pd->count[1] > 0) {
			l += snprintf(&lbuf[l],sizeof(lbuf)-l,"%-16s ",ibuf);
			l += ndpi_print_port_range(pt,pd->count[0]+pd->count[1],
					&lbuf[l],sizeof(lbuf)-l);
			l += snprintf(&lbuf[l],sizeof(lbuf)-l,"\n");
			}
		}
		if(count < l) break;
		
		if (!(access_ok(VERIFY_WRITE, buf+p, l) &&
				!__copy_to_user(buf+p, lbuf, l))) return -EFAULT;
		p += l;
		count -= l;
		(*ppos)++;
	      }
	      i++;
	    }
	    if (node->l) {
		if (node->r) {
		    *Xsp++ = node->r;
		}
		node = node->l;
		continue;
	    }
	    if (node->r) {
		node = node->r;
		continue;
	    }
	    node = Xsp != Xstack ? *(--Xsp): NULL;
	}
	return p;
}

static ssize_t
n_ipdef_proc_write(struct file *file, const char __user *buffer,
                     size_t length, loff_t *loff)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
	char buf[1025],cmd[512];
	int pos,cpos,bpos,l;

	if (length <= 0) return length;
	pos = 0; cpos = 0;
	memset(cmd,0,sizeof(cmd));

	while(pos < length) {
		l = min(length,sizeof(buf)-1);
	
		memset(buf,0,sizeof(buf));
		if (!(access_ok(VERIFY_READ, buffer+pos, l) && 
			!__copy_from_user(&buf[0], buffer+pos, l)))
			        return -EFAULT;
		for(bpos = 0; bpos < l; bpos++) {
			if(buf[bpos] == '\n') {
				if(parse_ndpi_ipdef(n,cmd)) return -EINVAL;
				cpos = 0;
				memset(cmd,0,sizeof(cmd));
				continue;
			}
			if(cpos < sizeof(cmd)-1)
				cmd[cpos++] = buf[bpos];
		}
		pos += l;
        }
	if(cpos) {
		if(parse_ndpi_ipdef(n,cmd)) return -EINVAL;
	}
        return length;
}

/********************* ndpi proto *********************************/

static int parse_ndpi_mark(char *cmd,struct ndpi_net *n) {
	char *v,*m,*hid;
	v = cmd;
	if(!*v) return 0;
/*
 * hexID hexmark/mask name
 */
	while(*v && (*v == ' ' || *v == '\t')) v++;
	if(*v == '#') return 0;
	hid = v;
	while(*v && !(*v == ' ' || *v == '\t')) v++;
	if(*v) *v++ = '\0';
	while(*v && (*v == ' ' || *v == '\t')) v++;
	for(m = v; *m ; m++) {
		if(*m != '#') continue;
		// remove comment 
		*m = '\0';
		// remove spaces before comment
		while (m--, m > v && (*m == ' ' || *m == '\t')) {
			*m = '\0';
		}
		break;
	}
	for(m = v; *m && *m != '/';m++);

	if(*m) {
		char *x;
		*m++ = '\0';
		x = m;
		while(*x && !(*x == ' ' || *x == '\t')) x++;
		if(*x) *x++ = '\0';
	}
	if(*v) {
		u_int32_t mark,mask;
		int id=-1;
		int i,any,all,ok;

		any = !strcmp(hid,"any");
		all = !strcmp(hid,"all");
		mark = 0;
		mask = 0xffff;
		if(kstrtoint(hid,16,&id)) {
			id = -1;
		} else {
			if(id < 0 || id > NDPI_LAST_IMPLEMENTED_PROTOCOL) {
				printk("NDPI: bad id %d\n",id);
				id = -1;
			}
		}
		if(!strncmp(v,"disable",7)) {
			mark = 0;
			mask = 0;
			m = v;
			if(any || all) {
				printk("NDPI: can't disable all\n");
				return 1;
			}
		} else {
		    if(kstrtou32(v,16,&mark)) {
			printk("NDPI: bad mark '%s'\n",v);
			return 1;
		    }
		    if(*m) {
			if(kstrtou32(m,16,&mask)) {
				printk("NDPI: bad mask '%s'\n",m);
				return 1;
			}
		    }
		}
//		printk("NDPI: proto %s id %d mark %x mask %s\n",
//				hid,id,mark,m);
		if(id != -1) {
			if(atomic_read(&n->protocols_cnt[0]) &&
				!mark && !mask) {
				printk("NDPI: can't disable protocol %s\n",
						prot_short_str[id]);
				return 1;
			}
			n->mark[id].mark = mark;
			if(*m) 	n->mark[id].mask = mask;
			return 0;
		}
		ok = 0;
		for(i=0; i < NDPI_LAST_IMPLEMENTED_PROTOCOL+1; i++) {
			if(!any && !all && strcmp(hid,prot_short_str[i])) continue;
			if(any && !i) continue;
			if(!any && !all && !mark && !mask) {
				if(atomic_read(&n->protocols_cnt[0])) {
					printk("NDPI: can't disable protocol %s\n",
							prot_short_str[id]);
				}
			}
			n->mark[i].mark = mark;
			if(*m) 	n->mark[i].mask = mask;
			ok++;
//			printk("Proto %s id %02x mark %08x/%08x\n",
//					cmd,i,n->mark[i].mark,n->mark[i].mask);
		}
		if(!ok) {
			printk("NDPI: unknown proto %s\n", hid);
			return 1;
		}
		return 0;
	}
	if(!strcmp(hid,"init")) {
		int i;
		for(i=0; i < NDPI_LAST_IMPLEMENTED_PROTOCOL+1; i++) {
			n->mark[i].mark = i;
			n->mark[i].mask = 0xff;
		}
		return 0;
	}
	printk("NDPI: bad cmd %s\n",hid);
	return *v ? 0:1;
}

static ssize_t nproto_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
	char lbuf[128];
	int i,l,p;

	for(i = 0,p = 0; i < NDPI_LAST_IMPLEMENTED_PROTOCOL+1; i++) {

		if(i < *ppos ) continue;
		l = i ? 0: snprintf(lbuf,sizeof(lbuf),
				"#id     mark ~mask     name   # count #version %s\n",
				NDPI_GIT_RELEASE);
		if(!n->mark[i].mark && !n->mark[i].mask)
		    l += snprintf(&lbuf[l],sizeof(lbuf)-l,"%02x  %17s %-16s # %d\n",
				i,"disabled",prot_short_str[i],
				atomic_read(&n->protocols_cnt[i]));
		else
		    l += snprintf(&lbuf[l],sizeof(lbuf)-l,"%02x  %8x/%08x %-16s # %d\n",
				i,n->mark[i].mark,n->mark[i].mask,prot_short_str[i],
				atomic_read(&n->protocols_cnt[i]));

		if(count < l) break;

		if (!(access_ok(VERIFY_WRITE, buf+p, l) &&
				!__copy_to_user(buf+p, lbuf, l))) return -EFAULT;
		p += l;
		count -= l;
		(*ppos)++;
	}
	return p;
}

static ssize_t
nproto_proc_write(struct file *file, const char __user *buffer,
                     size_t length, loff_t *loff)
{
        struct ndpi_net *n = PDE_DATA(file_inode(file));
	char buf[1025],cmd[64];
	int pos,cpos,bpos,l;

	if (length <= 0) return length;
	pos = 0; cpos = 0;
	memset(cmd,0,sizeof(cmd));

	while(pos < length) {
		l = min(length,sizeof(buf)-1);
	
		memset(buf,0,sizeof(buf));
		if (!(access_ok(VERIFY_READ, buffer+pos, l) && 
			!__copy_from_user(&buf[0], buffer+pos, l)))
			        return -EFAULT;
		for(bpos = 0; bpos < l; bpos++) {
			if(buf[bpos] == '\n') {
				if(parse_ndpi_mark(cmd,n)) return -EINVAL;
				cpos = 0;
				memset(cmd,0,sizeof(cmd));
				continue;
			}
			if(cpos < sizeof(cmd)-1)
				cmd[cpos++] = buf[bpos];
		}
		pos += l;
        }
	if(cpos) {
		if(parse_ndpi_mark(cmd,n)) return -EINVAL;
	}
        return length;
}

static const struct file_operations nproto_proc_fops = {
        .open    = ninfo_proc_open,
        .read    = nproto_proc_read,
        .write   = nproto_proc_write,
};

static const struct file_operations ninfo_proc_fops = {
        .open    = ninfo_proc_open,
        .read    = ninfo_proc_read,
        .write   = ninfo_proc_write,
};

#ifdef NDPI_DETECTION_SUPPORT_IPV6
static const struct file_operations ninfo6_proc_fops = {
        .open    = ninfo_proc_open,
        .read    = ninfo6_proc_read,
        .write   = ninfo_proc_write,
};
#endif
#ifdef BT_ANNOUNCE
static const struct file_operations nann_proc_fops = {
        .open    = ninfo_proc_open,
        .read    = nann_proc_read,
};
#endif

static const struct file_operations n_ipdef_proc_fops = {
        .open    = ninfo_proc_open,
        .read    = n_ipdef_proc_read,
        .write   = n_ipdef_proc_write,
};

static void __net_exit ndpi_net_exit(struct net *net)
{
	struct rb_node * next;
	struct osdpi_id_node *id;
	struct ndpi_net *n;

	n = ndpi_pernet(net);
	del_timer(&n->gc);

#ifndef NF_CT_CUSTOM
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	net->ct.label_words = n->labels_word;
#endif
	net->ct.labels_used--;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 1)
	nf_ct_iterate_cleanup(net, __ndpi_free_flow, n);
#else
	nf_ct_iterate_cleanup(net, __ndpi_free_flow, n, 0 ,0);
#endif
	/* free all objects before destroying caches */
	
	next = rb_first(&n->osdpi_id_root);
	while (next) {
		id = rb_entry(next, struct osdpi_id_node, node);
		next = rb_next(&id->node);
		rb_erase(&id->node, &n->osdpi_id_root);
		kmem_cache_free (osdpi_id_cache, id);
	}
	ndpi_exit_detection_module(n->ndpi_struct, free_wrapper);
	_report_alloc_mem();
	if(n->pde) {
		if(n->pe_ipdef)
			remove_proc_entry(ipdef_name, n->pde);
		if(n->pe_info)
			remove_proc_entry(info_name, n->pde);
		if(n->pe_proto)
			remove_proc_entry(proto_name, n->pde);
#ifdef BT_ANNOUNCE
		if(n->pe_ann)
			remove_proc_entry(ann_name, n->pde);
#endif
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		if(n->pe_info6)
			remove_proc_entry(info6_name, n->pde);
#endif
		PROC_REMOVE(n->pde,net);
	}
}

static int __net_init ndpi_net_init(struct net *net)
{
        int i;
	struct ndpi_net *n;

	/* init global detection structure */

	n = ndpi_pernet(net);
	spin_lock_init(&n->id_lock);
	spin_lock_init(&n->ipq_lock);

	parse_ndpi_mark("init",n);
       	n->osdpi_id_root = RB_ROOT;

	/* init global detection structure */
	n->ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
                                                     malloc_wrapper,
						     free_wrapper,
						     debug_printf);
	if (n->ndpi_struct == NULL) {
		pr_err("xt_ndpi: global structure initialization failed.\n");
                return -ENOMEM;
	}

	n->ndpi_struct->direction_detect_disable = 1;

        for (i = 0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
                atomic_set (&n->protocols_cnt[i], 0);
        }

	/* disable all protocols */
	NDPI_BITMASK_RESET(n->protocols_bitmask);
	ndpi_set_protocol_detection_bitmask2(n->ndpi_struct, &n->protocols_bitmask);
	if(bt_hash_size > 512) bt_hash_size = 512;
	if(bt_log_size > 512) bt_log_size = 512;
	if(bt_log_size < 32 ) bt_log_size = 0;
	ndpi_bittorrent_init(n->ndpi_struct,bt_hash_size*1024,bt_hash_tmo,bt_log_size);

	n->n_hash = -1;

	/* Create proc files */
	
	n->pde = proc_mkdir(dir_name, net->proc_net);
	if(!n->pde) {
		ndpi_exit_detection_module(n->ndpi_struct, free_wrapper);
		pr_err("xt_ndpi: cant create net/%s\n",dir_name);
		return -ENOMEM;
	}
	do {
		n->pe_info = NULL;
		n->pe_proto = NULL;
#ifdef BT_ANNOUNCE
		n->pe_ann = NULL;
#endif
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		n->pe_info6 = NULL;
#endif
		n->pe_ipdef = NULL;

		n->pe_info = proc_create_data(info_name, S_IRUGO | S_IWUSR,
					 n->pde, &ninfo_proc_fops, n);
		if(!n->pe_info) {
			pr_err("xt_ndpi: cant create net/%s/%s\n",dir_name,info_name);
			break;
		}
		n->pe_proto = proc_create_data(proto_name, S_IRUGO | S_IWUSR,
					 n->pde, &nproto_proc_fops, n);
		if(!n->pe_proto) {
			pr_err("xt_ndpi: cant create net/%s/%s\n",dir_name,proto_name);
			break;
		}
#ifdef BT_ANNOUNCE
		n->pe_ann = proc_create_data(ann_name, S_IRUGO,
					 n->pde, &nann_proc_fops, n);
		if(!n->pe_ann) {
			pr_err("xt_ndpi: cant create net/%s/%s\n",dir_name,ann_name);
			break;
		}

#endif
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		n->pe_info6 = proc_create_data(info6_name, S_IRUGO | S_IWUSR,
					 n->pde, &ninfo6_proc_fops, n);
		if(!n->pe_info6) {
			pr_err("xt_ndpi: cant create net/%s/%s\n",dir_name,info6_name);
			break;
		}

#endif
		n->pe_ipdef = proc_create_data(ipdef_name, S_IRUGO | S_IWUSR,
					 n->pde, &n_ipdef_proc_fops, n);
		if(!n->pe_ipdef) {
			pr_err("xt_ndpi: cant create net/%s/%s\n",dir_name,ipdef_name);
			break;
		}
		if(bt_hash_size) {
			init_timer(&n->gc);
			n->gc.data = (unsigned long)n;
			n->gc.function = bt_port_gc;
			n->gc.expires = jiffies + HZ/2;
			add_timer(&n->gc);
		}
#ifndef NF_CT_CUSTOM
		/* hack!!! */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
		n->labels_word = ACCESS_ONCE(net->ct.label_words);
		net->ct.label_words = 2;
#endif
		net->ct.labels_used++;
#endif
		/* All success! */
		return 0;
	} while(0);

/* rollback procfs on error */
	if(n->pe_ipdef)
		remove_proc_entry(ipdef_name,n->pde);
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	if(n->pe_info6)
		remove_proc_entry(proto_name, n->pde);
#endif
#ifdef BT_ANNOUNCE
	if(n->pe_ann)
		remove_proc_entry(ann_name, n->pde);
#endif
	if(n->pe_proto)
		remove_proc_entry(proto_name,n->pde);
	if(n->pe_info)
		remove_proc_entry(info_name,n->pde);

	PROC_REMOVE(n->pde,net);
	ndpi_exit_detection_module(n->ndpi_struct, free_wrapper);
	return -ENOMEM;
}

#ifndef NF_CT_CUSTOM
static void replace_nf_destroy(void)
{
	void (*destroy)(struct nf_conntrack *);
	rcu_read_lock();
	destroy = rcu_dereference(nf_ct_destroy);
	BUG_ON(destroy == NULL);
	rcu_assign_pointer(ndpi_nf_ct_destroy,destroy);
        RCU_INIT_POINTER(nf_ct_destroy, ndpi_destroy_conntrack);
	rcu_read_unlock();
}

static void restore_nf_destroy(void)
{
	void (*destroy)(struct nf_conntrack *);
	rcu_read_lock();
	destroy = rcu_dereference(nf_ct_destroy);
	BUG_ON(destroy != ndpi_destroy_conntrack);
	destroy = rcu_dereference(ndpi_nf_ct_destroy);
	BUG_ON(destroy == NULL);
	rcu_assign_pointer(nf_ct_destroy,destroy);
	rcu_read_unlock();
}
#else
static struct nf_ct_ext_type ndpi_extend = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
       .seq_print = seq_print_ndpi,
#endif
       .destroy   = nf_ndpi_free_flow,
       .len    = sizeof(struct nf_ct_ext_ndpi),
       .align  = __alignof__(uint32_t),
};
#endif

static struct pernet_operations ndpi_net_ops = {
        .init   = ndpi_net_init,
        .exit   = ndpi_net_exit,
        .id     = &ndpi_net_id,
        .size   = sizeof(struct ndpi_net),
};


static int __init ndpi_mt_init(void)
{
        int ret;

	ndpi_size_id_struct = sizeof(struct osdpi_id_node);
	ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
	detection_tick_resolution = HZ;

	if(request_module("nf_conntrack") < 0) {
		pr_err("xt_ndpi: nf_conntrack required!\n");
		return -EOPNOTSUPP;
	}
	if(request_module("ip_tables") < 0) {
		pr_err("xt_ndpi: ip_tables required!\n");
		return -EOPNOTSUPP;
	}
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	if(request_module("ip6_tables") < 0) {
		pr_err("xt_ndpi: ip6_tables required!\n");
		return -EOPNOTSUPP;
	}
#endif
#ifdef NF_CT_CUSTOM
	ret = nf_ct_extend_custom_register(&ndpi_extend,0x4e445049); /* "NDPI" in hex */
	if(ret < 0) {
		pr_err("xt_ndpi: can't nf_ct_extend_register.\n");
		return -EBUSY;
	}
	nf_ct_ext_id_ndpi = ndpi_extend.id;
#else
	nf_ct_ext_id_ndpi = NF_CT_EXT_LABELS;
#endif

	ret = register_pernet_subsys(&ndpi_net_ops);
	if (ret < 0) {
		pr_err("xt_ndpi: can't register_pernet_subsys.\n");
		goto unreg_ext;
	}

        ret = xt_register_match(&ndpi_mt_reg);
        if (ret) {
                pr_err("xt_ndpi: error registering ndpi match.\n");
		goto unreg_pernet;
        }

        ret = xt_register_target(&ndpi_tg_reg);
        if (ret) {
                pr_err("xt_ndpi: error registering ndpi match.\n");
		goto unreg_match;
        }

	ret = -ENOMEM;

        osdpi_flow_cache = kmem_cache_create("ndpi_flows", ndpi_size_flow_struct,
                                             0, 0, NULL);
        if (!osdpi_flow_cache) {
                pr_err("xt_ndpi: error creating flow cache.\n");
		goto unreg_target;
        }
        
        osdpi_id_cache = kmem_cache_create("ndpi_ids",
                                           ndpi_size_id_struct,
                                           0, 0, NULL);
        if (!osdpi_id_cache) {
		pr_err("xt_ndpi: error creating id cache.\n");
		goto free_flow;
	}

	ndpi_size_hash_ip4p_node=                sizeof(struct hash_ip4p_node)
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		                                 +12
#endif
	;

        bt_port_cache = kmem_cache_create("ndpi_btport",
				ndpi_size_hash_ip4p_node, 0, 0, NULL);
        if (!bt_port_cache) {
		pr_err("xt_ndpi: error creating port cache.\n");
		goto free_id;
	}
	if(bt_hash_size && bt_hash_size > 32) bt_hash_size = 32;
	if(!bt_hash_tmo) bt_hash_tmo = 900;
	if( bt_hash_tmo > 3600) bt_hash_tmo = 3600;

#ifndef NF_CT_CUSTOM
	replace_nf_destroy();
#endif
	pr_info("xt_ndpi v1.2 ndpi %s %s\n"
		" bt hash size %luk gc timeout %ld sec\n"
		" sizeof hash_ip4p_node  %zu\n"
		" sizeof id_struct %zu\n"
		" sizeof flow_struct %zu\n"
		"  sizeof packet_struct %zu\n"
		"  sizeof flow_tcp_struct %zu\n"
		"  sizeof flow_udp_struct %zu\n"
		"  sizeof int_one_line_struct %zu\n"
		" sizeof ndpi_ip_addr_t %zu\n"
		" sizeof ndpi_protocol %zu\n"
		" sizeof nf_ct_ext_ndpi %zu\n"
		" sizeof spinlock_t %zu\n"
#ifndef NF_CT_CUSTOM
		" NF_LABEL_ID %d\n",
#else
		" NF_EXT_ID %d\n",
#endif
		NDPI_GIT_RELEASE,
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		"with IPv6",
#else
		"without IPv6",
#endif
		bt_hash_size,bt_hash_tmo,
		ndpi_size_hash_ip4p_node,
		ndpi_size_id_struct,ndpi_size_flow_struct,
		sizeof(struct ndpi_packet_struct),
		sizeof(struct ndpi_flow_tcp_struct),
		sizeof(struct ndpi_flow_udp_struct),
		sizeof(struct ndpi_int_one_line_struct),
		sizeof(ndpi_ip_addr_t),
		sizeof(ndpi_protocol),
		sizeof(struct nf_ct_ext_ndpi),
		sizeof(spinlock_t),
		nf_ct_ext_id_ndpi);
	return 0;

free_id:
       	kmem_cache_destroy (osdpi_id_cache);
free_flow:
       	kmem_cache_destroy (osdpi_flow_cache);
unreg_target:
	xt_unregister_target(&ndpi_tg_reg);
unreg_match:
	xt_unregister_match(&ndpi_mt_reg);
unreg_pernet:
	unregister_pernet_subsys(&ndpi_net_ops);
unreg_ext:
#ifdef NF_CT_CUSTOM
	nf_ct_extend_unregister(&ndpi_extend);
#endif
       	return ret;
}


static void __exit ndpi_mt_exit(void)
{
	pr_info("xt_ndpi 1.2 unload.\n");

        kmem_cache_destroy (bt_port_cache);
        kmem_cache_destroy (osdpi_id_cache);
        kmem_cache_destroy (osdpi_flow_cache);
	xt_unregister_target(&ndpi_tg_reg);
	xt_unregister_match(&ndpi_mt_reg);
	unregister_pernet_subsys(&ndpi_net_ops);
#ifdef NF_CT_CUSTOM
	nf_ct_extend_unregister(&ndpi_extend);
#else
	restore_nf_destroy();
#endif
}


module_init(ndpi_mt_init);
module_exit(ndpi_mt_exit);

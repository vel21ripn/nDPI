#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>

#include <linux/ip.h>
#include <linux/ipv6.h>

#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack_ecache.h>

#include "ndpi_config.h"
#undef HAVE_HYPERSCAN
#include "ndpi_main.h"
#include "ndpi_private.h"

#define uthash_malloc(sz) ndpi_malloc(sz)
#define uthash_free(ptr,sz) ndpi_free(ptr)

#include "third_party/include/uthash.h"

#include "ndpi_strcol.h"
#include "ndpi_main_common.h"
#include "ndpi_main_netfilter.h"
#include "ndpi_proc_parsers.h"
#include "ndpi_proc_generic.h"
#include "ndpi_proc_hash.h"

/* copy from src/lib/ndpi_utils.c */

typedef struct {
  char *key;
  u_int64_t value64;
  ndpi_list value_list;
  UT_hash_handle hh;
} ndpi_str_hash_priv;

typedef int (*ndpi_hash_walk_iter2)(char *key, u_int64_t value64, void *data);

int ndpi_hash_walk2(ndpi_str_hash **h, ndpi_hash_walk_iter2 cb, void *data) {
  if(h && *h) {
    ndpi_str_hash_priv *h_priv = (ndpi_str_hash_priv *)((*h)->priv);
    ndpi_str_hash_priv *curr, *tmp;

    HASH_ITER(hh, h_priv, curr, tmp) {
      if(cb(curr->key, curr->value64, data)) return 1;
    }
  }
  return 0;
}

/* copy from src/lib/ndpi_utils.c */

struct nhash_ws {
	loff_t		ppos;
	char		*u_buf;
	size_t		count;

	loff_t		pos;

	size_t		output;
	int		err,eob;
};

#define h_buf_size 128

static noinline int nhash_walker(char *key, u_int64_t value64, void *data) {
	struct nhash_ws *ws = (struct nhash_ws *)data;
	char *head;
	size_t copy_len = 0, offs = 0, skip = 0, k_len;
	loff_t ppos_end = ws->ppos + ws->count - 1;
	loff_t pos_end;
	char h_buf[h_buf_size+2];

	k_len = strlen(key)+1;
	pos_end  = ws->pos + k_len - 1;

	if(_DBG_TRACE_GPROC)
	  pr_info("%s: buf %lld-%lld[%d] data %lld-%lld[%d]\n",__func__,
			  ws->ppos, ppos_end, (int)ws->count,
			  ws->pos, pos_end, (int)k_len);

	if(!ws->count || ws->pos > ppos_end) { // buffer is full 
		ws->eob = 1; 
		return 1; 
	}
	if(pos_end < ws->ppos) {
		ws->pos += k_len;
		return 0;
	}
	if(k_len > h_buf_size-2) { // BUG! 
		pr_err("%s: error: key length %d > %d\n",__func__,(int)k_len, (int)h_buf_size-1);
		ws->err = EINVAL;
		return 1; 
	}

	memcpy(h_buf,key,k_len-1);
	h_buf[k_len-1] = '\n';
	h_buf[k_len] = '\0';
	head = h_buf;
	copy_len = k_len;

	if(ws->pos < ws->ppos) {
		// if(ws->pos + k_len - 1 < ws->ppos) { } // imposible!
		if(pos_end > ppos_end) { // k b b k
			k_len = ws->ppos+ws->count - ws->pos;
			ws->eob = 1;
		}
		copy_len = ws->pos + k_len - ws->ppos; // k b bk
		skip = k_len - copy_len;
		head += skip;
	} else {
		// if(ws->pos > ws->ppos + ws->count - 1) { } // inposible!
		if(pos_end > ppos_end) { //  b k b k
			copy_len = ws->ppos + ws->count - ws->pos;
			ws->eob = 1;
		}
		if(ws->pos > ws->ppos)  { // b k bk
			offs = ws->pos - ws->ppos;
		}
	}
	if(copy_len != 0) {
	    if(_DBG_TRACE_GPROC)
	      pr_info("%s: copy key skip:%d size:%d offs:%d '%.*s'\n",__func__,
			(int)skip, (int)copy_len, (int)offs,(int)copy_len,head);
	    memcpy(ws->u_buf+offs, head, copy_len);
	}
	copy_len   += offs;
	ws->ppos   += copy_len;
	ws->u_buf  += copy_len;
	ws->output += copy_len;
	ws->pos    += copy_len + skip;
	ws->count  -= copy_len;
	if(!ws->count) {
		ws->eob = 1;
		return 1;
	}
	return 0;
}

ssize_t nhash_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
        struct ndpi_net *n =  pde_data(file_inode(file));
	size_t buf_len = count;
	char *tmp_buf;

	struct nhash_ws ws = { .pos = 0, .ppos = *ppos, .eob = 0, .err = 0};

	if(!n->ndpi_hash) {
	    if(!*ppos) {
		static const char msg[] = "hash disabled\n";
		size_t l = sizeof(msg)-1;
		if ( copy_to_user(buf, msg, l)) return -EFAULT;
		(*ppos) += l;
		return l;
	    }
	    return 0;
	}
	if(_DBG_TRACE_GPROC)
	    pr_info("%s: start: buf %lld-%lld[%d] total %u\n",__func__, 
			    ws.ppos,ws.ppos+count-1,(int)count,(unsigned int)n->ndpi_hash->stats.n_keys_size);

	if(*ppos >= n->ndpi_hash->stats.n_keys_size) {
		return 0;
	}
	buf_len = count;
	if(buf_len > 16384) buf_len = 16384;
	// < 32k
	tmp_buf = kmalloc(buf_len,GFP_KERNEL);
	if(!tmp_buf) return -ENOMEM;

	ws.u_buf = tmp_buf;
	ws.count = buf_len;

	read_lock(&n->ndpi_struct->hash_map_lock);
	ndpi_hash_walk2(&n->ndpi_hash, nhash_walker, (void *)&ws);
	read_unlock(&n->ndpi_struct->hash_map_lock);
	if(_DBG_TRACE_GPROC)
	  pr_info("%s: end: ppos %lld-%lld:%d, pos %lld-%lld:%d, %s err %d\n",__func__,
			*ppos,ws.ppos-1,(int)ws.count, ws.pos-ws.output,ws.pos-1,(int)ws.output,
			ws.eob ? " EOF, ":"",ws.err);
	*ppos = ws.ppos;
	if(ws.output && copy_to_user(buf,tmp_buf,ws.output))
		ws.err = EFAULT;
	kfree(tmp_buf);
	if(ws.err)
		return -ws.err;
	return ws.output;
}
static void ndpi_hash_sync(struct ndpi_net *n) {

	write_lock(&n->ndpi_struct->hash_map_lock);
	switch(n->ndpi_hash_src) {
	  case 1: n->ndpi_struct->malicious_ja4_hashmap = n->ndpi_hash;
		  break;
	  case 2: n->ndpi_struct->malicious_sha1_hashmap = n->ndpi_hash;
		  break;
	  default:
		  pr_err("%s: BUG ndpi_hash_src %d\n",__func__,n->ndpi_hash_src);
	}
	write_unlock(&n->ndpi_struct->hash_map_lock);
}

int parse_ndpi_hash(struct ndpi_net *n,char *cmd) {
	size_t c_len = strlen(cmd);
	if(_DBG_TRACE_SPROC)
	  pr_info("NDPI: hash %s\n",cmd);
	
	if(!n->ndpi_hash) return 1;
	if(*cmd == '+') {
		if(c_len > h_buf_size - 2) {
			pr_info("NDPI: Error: hash too long\n");
			return 1;
		}
		write_lock(&n->ndpi_struct->hash_map_lock);
		int r = ndpi_hash_add_entry(&n->ndpi_hash,cmd+1,c_len-1,1ULL,NULL);
		write_unlock(&n->ndpi_struct->hash_map_lock);
		if(r > 1) {
			pr_info("NDPI: add hash %s error %d\n",cmd+1,r);
			return 1;
		}
		n->ndpi_hash->stats.n_keys_size += c_len;
		return 0;
	} else if(*cmd == '-') { // clean;
		write_lock(&n->ndpi_struct->hash_map_lock);
		ndpi_hash_free(&n->ndpi_hash);
		ndpi_hash_init(&n->ndpi_hash);
		n->ndpi_hash->stats.n_keys_size = 0;
		write_unlock(&n->ndpi_struct->hash_map_lock);
		ndpi_hash_sync(n);
		return 0;
	} else
		return 1;
}

ssize_t nhash_proc_write(struct file *file, const char __user *buffer,
                     size_t length, loff_t *loff)
{
        return generic_proc_write(pde_data(file_inode(file)), buffer, length, loff,
                        parse_ndpi_hash, 256, W_BUF_HASH);
}

int nhash_proc_close(struct inode *inode, struct file *file)
{
        struct ndpi_net *n = pde_data(file_inode(file));
        generic_proc_close(n,parse_ndpi_hash,W_BUF_HASH);
	ndpi_hash_sync(n);
	n->ndpi_hash = NULL;
        return 0;
}

int nhash_ja4_proc_open(struct inode *inode, struct file *file) {
	struct ndpi_net *n = pde_data(file_inode(file));

	if(cmpxchg(&n->ndpi_hash,NULL,n->ndpi_struct->malicious_ja4_hashmap) != NULL)
		return -EBUSY;
	n->ndpi_hash_src = 1;
	return 0;
}

int nhash_sha1_proc_open(struct inode *inode, struct file *file) {
	struct ndpi_net *n = pde_data(file_inode(file));

	if(cmpxchg(&n->ndpi_hash,NULL,n->ndpi_struct->malicious_sha1_hashmap) != NULL)
		return -EBUSY;
	n->ndpi_hash_src = 2;
	return 0;
}



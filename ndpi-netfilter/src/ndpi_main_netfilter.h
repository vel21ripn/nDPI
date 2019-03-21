
#ifdef NDPI_IPPORT_DEBUG
#undef DP
#define DP(fmt, args...) printk(fmt, __func__, ## args)
#define DBGDATA(a...) a;
#warning  "DEBUG code"
#else
#define DP(fmt, args...)
#define DBGDATA(a...)
#endif

typedef struct ndpi_detection_module_struct ndpi_mod_str_t;

typedef enum write_buf_id {
	W_BUF_IP=0,
	W_BUF_HOST,
	W_BUF_PROTO,
	W_BUF_LAST
} write_buf_id_t;

struct write_proc_cmd {
	uint32_t  cpos,max;
	char      cmd[0];
};

struct ndpi_net {
	struct ndpi_detection_module_struct *ndpi_struct;
	struct rb_root osdpi_id_root;
	NDPI_PROTOCOL_BITMASK protocols_bitmask;
	atomic_t	protocols_cnt[NDPI_NUM_BITS+1];
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
				*pe_hostdef,
				*pe_ipdef;
	int		n_hash;
	int		gc_count;
	int		gc_index;
	int		labels_word;
        struct		timer_list gc;

	spinlock_t	host_lock; /* protect host_ac, hosts, hosts_tmp */
	hosts_str_t	*hosts;
	
	hosts_str_t	*hosts_tmp;
	void		*host_ac;
	int		host_error;

	spinlock_t	       w_buff_lock;
	struct write_proc_cmd *w_buff[W_BUF_LAST];

	struct ndpi_mark {
		uint32_t	mark,mask;
	} mark[NDPI_NUM_BITS+1];
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	u_int8_t debug_level[NDPI_NUM_BITS+1];
#endif
};

extern unsigned long ndpi_log_debug;

const char *acerr2txt(AC_ERROR_t r);
void set_debug_trace( struct ndpi_net *n);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define ACCESS_OK(a,b,c) access_ok(b,c)
#else
#define ACCESS_OK(a,b,c) access_ok(a,b,c)
#endif


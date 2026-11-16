#ifdef NDPI_ENABLE_DEBUG_MESSAGES

struct dbg_ipt_names {
	uint32_t mask;
	const char *name;
};
int dbg_ipt_opt(char *lbuf,size_t count);
uint32_t dbg_ipt_opt_get(const char *lbuf);

#endif

struct nf_ct_ext_ndpi;
struct  ndpi_net;

void ndpi_ipt_debug_printf(u_int16_t protocol, struct ndpi_detection_module_struct *id_struct,
		ndpi_log_level_t log_level, const char *file_name,
		const char *func_name, unsigned line_number,
		const char * format, ...);

void set_debug_trace( struct ndpi_net *n);

void print_ct_ndpi(struct nf_ct_ext_ndpi *ct_ndpi);

char *ct_info(const struct nf_conn * ct,char *buf,size_t buf_size,int dir);

void packet_trace(const struct sk_buff *skb,const struct nf_conn * ct,
	struct nf_ct_ext_ndpi *ct_ndpi,int ct_dir,const char *msg, const char *format, ...);


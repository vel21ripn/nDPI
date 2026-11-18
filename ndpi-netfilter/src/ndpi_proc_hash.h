
int nhash_ja4_proc_open(struct inode *inode, struct file *file);
int nhash_sha1_proc_open(struct inode *inode, struct file *file);
ssize_t nhash_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
ssize_t nhash_proc_write(struct file *file, const char __user *buffer, size_t length, loff_t *loff);
int nhash_proc_close(struct inode *inode, struct file *file);
int parse_ndpi_hash(struct ndpi_net *n,char *cmd);


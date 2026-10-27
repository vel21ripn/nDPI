#ifndef _LONG_LIST_HEAD
#define _LONG_LIST_HEAD 1

#define A_LIST_SIZE 250
#define A_LIST_LAST (A_LIST_SIZE-1)

struct long_list {
	struct list_head list;
	spinlock_t	lock;
	struct a_list	*empty;
	struct a_list	*curr;
	int		index;
	int		allocated;
	int		counter; // total elements
};

struct a_list {
	struct list_head list;
	int head,counter;
#ifdef A_LIST_DBG
	int id;
#endif
	void *data[A_LIST_SIZE+1];
};

struct long_list *long_list_init(struct long_list *t);
int long_list_insert(struct long_list *ll,void *data);
int long_list_delete_current(struct long_list *ll);
struct a_list * long_list_next(struct long_list *ll);
void * long_list_current(struct long_list *ll);
void long_list_free(struct long_list *ll);
void long_list_start(struct long_list *ll);
void long_list_reset(struct long_list *ll);

#endif

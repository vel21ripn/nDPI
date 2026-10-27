
#include <linux/kernel.h> /* Needed for KERN_ALERT       */
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "ndpi_long_list.h"

#ifdef A_LIST_DBG
static int id_block=1;
#endif

static struct a_list *a_list_init(struct long_list *ll);
static int _long_list_delete(struct long_list *ll,struct a_list *t,int index);
static struct a_list * _long_list_next(struct long_list *ll);

static inline void _long_list_reset(struct long_list *ll) {
	ll->curr   = NULL;
	ll->index     = A_LIST_SIZE;
}

struct long_list *long_list_init(struct long_list *ll) {
	spin_lock_init(&ll->lock);
	INIT_LIST_HEAD(&ll->list);
	ll->empty  = NULL;
	_long_list_reset(ll);
	ll->allocated = 0;
	ll->counter   = 0;
	return ll;
}

/* 
 * return new array and lock list else unlock list
 */

static struct a_list *a_list_init(struct long_list *ll) {
	struct a_list *t;
	int unlocked = 0;

	if((t = xchg(&ll->empty,NULL)) == NULL) {
		spin_unlock(&ll->lock);
		t = kmalloc(sizeof(struct a_list),GFP_ATOMIC);
		if(!t) return NULL; 
		unlocked = 1;
	}
	INIT_LIST_HEAD(&t->list);
#ifdef A_LIST_DBG
	t->id = id_block++;
#endif
	t->head    = A_LIST_SIZE;
	t->data[A_LIST_SIZE] = NULL;
	t->counter = 0;
	ll->allocated++;
	if(unlocked) spin_lock(&ll->lock);
	list_add(&t->list,&ll->list);
	return t;
}

/*
 * return:
 *  0 - success
 *  1 - no memory
 *  2 - bug
 */

int long_list_insert(struct long_list *ll,void *data) {
	struct a_list *t;
	int ret = 1;
	spin_lock_bh(&ll->lock);
	do {
		if(list_empty(&ll->list)) {
			t = a_list_init(ll);
			if(!t) return ret;
		} else {
			t = list_first_entry(&ll->list,struct a_list, list);
		}
		if(!t->head) {
			if(t->counter == A_LIST_SIZE) {
				t = a_list_init(ll);
				if(!t) return ret;
			} else {
				void **d = &t->data[t->head+1];
				/* t->data[A_LIST_SIZE] is NULL */
				while(*d) d++;

				if( d != &t->data[A_LIST_SIZE]) {
					*d = data;
					t->counter++;
					ll->counter++;
					ret = 0;
				} else {
					pr_err("%s: BUG! i == A_LIST_SIZE\n",__func__);
					ret = 2;
				}
				break;
			}
		}
		t->data[--t->head] = data;
		t->counter++;
		ll->counter++;
		ret = 0;
	} while(0);
	spin_unlock_bh(&ll->lock);
	return ret;
}

/*
 * return
 *   0: no data
 *   1: simple delete
 *   2: long delete
 */

static int _long_list_delete(struct long_list *ll,struct a_list *t,int index) {
	void *data;
	int ret = 0;
	spin_lock_bh(&ll->lock);

	if(ll->curr && ll->curr == t && ll->index == index) {
		_long_list_next(ll);
	}
	do {
		data = xchg(&t->data[index],NULL);
		if(!data) break;
		ll->counter--;
		t->counter--;
		if(t->counter) { // nonempty block
			while(!t->data[t->head]) // move head if needed
				t->head++;
			if(t->head  == A_LIST_SIZE)
				pr_err("%s: BUG! t->head  == A_LIST_SIZE\n",__func__);

			ret = 1;
			break;
		}
		list_del(&t->list);
		if(!ll->empty)
			ll->empty = t;
		    else 
			kfree(t);
		ll->allocated--;
		ret = 2;
	} while(0);
	spin_unlock_bh(&ll->lock);
	return ret;
}

int long_list_delete_current(struct long_list *ll) {
	return ll->curr ? _long_list_delete(ll,ll->curr,ll->index):0;
}

static struct a_list * _long_list_next(struct long_list *ll) {
	struct a_list *t;

	t = ll->curr;
	if(!t) return t;

	ll->index++;
	do {
		while(ll->index < A_LIST_SIZE) {
			if(t->data[ll->index])	return t;
			ll->index++;
		}
		if(ll->index >= A_LIST_SIZE) {
			if(list_is_last(&t->list,&ll->list)) {
				_long_list_reset(ll);
				return NULL;
			}
			t = ll->curr = list_next_entry(t, list);
			ll->index = ll->curr->head;
		}
	} while(1);
	return NULL;
}

struct a_list * long_list_next(struct long_list *ll) {
	struct a_list *t;
	spin_lock_bh(&ll->lock);
	t = _long_list_next(ll);
	spin_unlock_bh(&ll->lock);
	return t;
}

void * long_list_current(struct long_list *ll) {
	struct a_list *t;
	void *d = NULL;

	spin_lock_bh(&ll->lock);
	t = ll->curr;
	if(t) {
		d = t->data[ll->index];
		if(!d) {
			// pr_err("%s: BUG !ll->index %d:%d\n",__func__,t->id,ll->index);
			ll->curr = NULL;
			ll->index = A_LIST_SIZE;
		}
	}
	spin_unlock_bh(&ll->lock);
	return d;
}

void long_list_start(struct long_list *ll) {
	struct a_list *t;

	spin_lock_bh(&ll->lock);
	_long_list_reset(ll);
	t = list_first_entry_or_null(&ll->list,struct a_list, list);
	if(t) {
		ll->curr = t;
		ll->index = t->head;
	}
	spin_unlock_bh(&ll->lock);
}

void long_list_reset(struct long_list *ll) {
	spin_lock_bh(&ll->lock);
	_long_list_reset(ll);
	spin_unlock_bh(&ll->lock);
}

void long_list_free(struct long_list *ll) {
	struct a_list *t,*n;

	spin_lock_bh(&ll->lock);
	t = list_first_entry_or_null(&ll->list,struct a_list, list);
	while(t) {
		if(list_is_last(&t->list,&ll->list)) break;
		n = list_next_entry(t, list);
		list_del(&t->list);
		ll->allocated--;
		t = n;
	}
	if(ll->empty) kfree(ll->empty);
	spin_unlock_bh(&ll->lock);
}


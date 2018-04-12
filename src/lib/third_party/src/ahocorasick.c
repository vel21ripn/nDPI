/*
 * ahocorasick.c: implementation of ahocorasick library's functions
 * This file is part of multifast.
 *
 Copyright 2010-2012 Kamiar Kanani <kamiar.kanani@gmail.com>

 multifast is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 multifast is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with multifast.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#else
#include <asm/byteorder.h>
#include <linux/kernel.h>
typedef __kernel_size_t size_t;
#endif

#include "ndpi_api.h"
#include "ahocorasick.h"

/* Allocation step for automata.all_nodes */
#define REALLOC_CHUNK_ALLNODES 200

/* Private function prototype */
static void ac_unregister_match_node (AC_AUTOMATA_t * thiz, AC_NODE_t * node);
static void ac_automata_register_nodeptr (AC_AUTOMATA_t * thiz, AC_NODE_t * node);
static void ac_automata_unregister_nodeptr (AC_AUTOMATA_t * thiz, AC_NODE_t * rnode);
static void ac_automata_union_matchstrs (AC_NODE_t * node);
static void ac_automata_set_failure
		(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas);
static void ac_automata_traverse_setfailure
		(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas);


/******************************************************************************
 * FUNCTION: ac_automata_init
 * Initialize automata; allocate memories and set initial values
 * PARAMS:
 * MATCH_CALBACK mc: call-back function
 * the call-back function will be used to reach the caller on match occurrence
 ******************************************************************************/
AC_AUTOMATA_t * ac_automata_init (MATCH_CALBACK_f mc)
{
  AC_AUTOMATA_t * thiz = (AC_AUTOMATA_t *)ndpi_malloc(sizeof(AC_AUTOMATA_t));
  memset (thiz, 0, sizeof(AC_AUTOMATA_t));
  thiz->root = node_create ();
  thiz->all_nodes_max = REALLOC_CHUNK_ALLNODES;
  thiz->all_nodes = (AC_NODE_t **) ndpi_malloc (thiz->all_nodes_max*sizeof(AC_NODE_t *));
  thiz->match_callback = mc;
  ac_automata_register_nodeptr (thiz, thiz->root);
  ac_automata_reset (thiz);
  thiz->total_patterns = 0;
  thiz->automata_open = 1;
  return thiz;
}

/******************************************************************************
 * FUNCTION: ac_automata_add
 * Adds pattern to the automata.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * AC_PATTERN_t * patt: the pointer to added pattern
 * RETUERN VALUE: AC_ERROR_t
 * the return value indicates the success or failure of adding action
 ******************************************************************************/
AC_ERROR_t ac_automata_add (AC_AUTOMATA_t * thiz, AC_PATTERN_t * patt)
{
  unsigned int i;
  AC_NODE_t * n = thiz->root;
  AC_NODE_t * next;
  AC_ALPHABET_t alpha;

  if(!thiz->automata_open)
    return ACERR_AUTOMATA_CLOSED;

  if (!patt->length)
    return ACERR_ZERO_PATTERN;

  if (patt->length > AC_PATTRN_MAX_LENGTH)
    return ACERR_LONG_PATTERN;

  for (i=0; i<patt->length; i++)
    {
      alpha = patt->astring[i];
      if ((next = node_find_next_inc(n, alpha)))
	{
	  n = next;
	  continue;
	}
      else
	{
	  next = node_create_next(n, alpha);
	  next->depth = n->depth + 1;
	  n = next;
	  ac_automata_register_nodeptr(thiz, n);
	}
    }

  if(thiz->max_str_len < patt->length)
    thiz->max_str_len = patt->length;

  if(n->final)
    return ACERR_DUPLICATE_PATTERN;

  n->final = 1;
  node_register_matchstr(n, patt);
  thiz->total_patterns++;

  return ACERR_SUCCESS;
}

struct ac_path {
	AC_NODE_t * n;
	unsigned int idx,l;
};

AC_ERROR_t ac_automata_del (AC_AUTOMATA_t * thiz, AC_PATTERN_t * patt)
{
  int i,j;
  AC_NODE_t * n = thiz->root;
  AC_NODE_t * next;
  AC_ALPHABET_t alpha;
  struct ac_path *path;

  if(!thiz->automata_open)
    return ACERR_AUTOMATA_CLOSED;

  if (!patt->length)
    return ACERR_ZERO_PATTERN;

  if (patt->length > AC_PATTRN_MAX_LENGTH)
    return ACERR_LONG_PATTERN;

  path = ndpi_malloc(sizeof(struct ac_path) * (patt->length + 1));
  if(!path)
	return ACERR_ERROR;


  for (i=0; n && i<patt->length; i++)
    {
      alpha = patt->astring[i];
      
      for (j=0; j < n->outgoing_degree; j++)	{
	    if(!n->outgoing[j].count) continue;
	    if(n->outgoing[j].alpha == alpha) break;
      }
      if(j > n->outgoing_degree) {
	    ndpi_free(path);
	    return ACERR_ERROR;
      }
      path[i].n = n;
      path[i].idx = j;
      n = n->outgoing[j].next;
    }
  if(!n || !n->matched_patterns_num) {
	    ndpi_free(path);
	    return ACERR_ERROR;
  }
  ac_unregister_match_node (thiz, n);

  do {
	i--;
	n = path[i].n;
	j = path[i].idx;
        alpha = n->outgoing[j].alpha;

	if(--n->outgoing[j].count > 0) continue;
	next = n->outgoing[j].next;
	n->outgoing[j].next = NULL;
	if(next) {
	  	ac_automata_unregister_nodeptr(thiz, next);
		node_release(next);
	}
  } while(i > 0);

  thiz->total_patterns--;

  ndpi_free(path);

  return ACERR_SUCCESS;
}

void ac_register_match_node (AC_AUTOMATA_t * thiz, AC_NODE_t * node)
{
  unsigned int i;
  if(!thiz->match_nodes) {
	  thiz->match_nodes = ndpi_calloc(thiz->total_patterns+1, sizeof (*thiz->match_nodes));
	  if(!thiz->match_nodes) return;
	  thiz->total_patterns_max = thiz->total_patterns+1;
  }
  for(i=0; i < thiz->total_patterns_num; i++) {
	  if(thiz->match_nodes[i] == node->id) return;
  }
  if(thiz->total_patterns_num >= thiz->total_patterns_max) {
	  int newsize = thiz->total_patterns_max + 64;
	  unsigned long *newptr = ndpi_realloc(thiz->match_nodes, 
			  thiz->total_patterns_max * sizeof (*thiz->match_nodes),
			  		   newsize * sizeof (*thiz->match_nodes));
	  if(!newptr) return;
	  thiz->match_nodes = newptr;
	  thiz->total_patterns_max = newsize;
  }
  thiz->match_nodes[thiz->total_patterns_num] = node->id;
  thiz->total_patterns_num++;
}

static void ac_unregister_match_node (AC_AUTOMATA_t * thiz, AC_NODE_t * node) {
  unsigned int i;

  if(node->matched_patterns_num != 1) return;
  if(!thiz->match_nodes || !thiz->total_patterns_num) return;

  for(i=0; i < thiz->total_patterns_num; i++) {
	  if(thiz->match_nodes[i] != node->id) continue;
	  if(i < thiz->total_patterns_num-1)
	  	thiz->match_nodes[i] = thiz->match_nodes[thiz->total_patterns_num-1];
	  thiz->total_patterns_num--;
	  return;
  }
}

char *ac_automata_get_match(AC_AUTOMATA_t * thiz, unsigned int num, unsigned short int *proto) {
  unsigned int i;
  AC_NODE_t * node;

  if(!thiz->match_nodes || num >= thiz->total_patterns_num) return NULL;
  i = thiz->match_nodes[num];
  if(i >= thiz->all_nodes_num) return NULL;
  node = thiz->all_nodes[i];
  if(!node || !node->matched_patterns_num || node->outgoing_degree) return NULL;
  *proto = node->matched_patterns[0].rep.number;
  return node->matched_patterns[0].astring;
}

static void ac_automata_unregister_nodeptr (AC_AUTOMATA_t * thiz, AC_NODE_t * rnode)
{
  unsigned int i,j;
  struct edge * e;
  AC_NODE_t * node;

    if(rnode == thiz->all_nodes[0]) return; // cannot delete root!

    for (i=0; i < thiz->all_nodes_num; i++) {
	node = thiz->all_nodes[i];
	if(!node) continue;
	if(node == rnode) {
		thiz->all_nodes[i] = NULL;
		continue;
	}
	if(node->failure_node == rnode)
		node->failure_node = NULL;
	for(j=0; j < node->outgoing_degree; j++) {
		e = &node->outgoing[j];
		if(!e->count) continue;
		if(e->next == rnode) {
//		    printf("Delete ref from NODE(%3d) '%c'\n",node->id,e->alpha);
		    if(--e->count != 0)
#ifdef __KERNEL__
			    BUG_ON("e->count != 0");
#else
			    abort();
#endif
		}
	}
    }
}


/******************************************************************************
 * FUNCTION: ac_automata_finalize
 * Locate the failure node for all nodes and collect all matched pattern for
 * every node. it also sorts outgoing edges of node, so binary search could be
 * performed on them. after calling this function the automate literally will
 * be finalized and you can not add new patterns to the automate.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 ******************************************************************************/
void ac_automata_finalize (AC_AUTOMATA_t * thiz)
{
  unsigned int i,max_str_len = 0;
  AC_ALPHABET_t *alphas;
  AC_NODE_t * node;

  if((alphas = ndpi_malloc(AC_PATTRN_MAX_LENGTH)) != NULL) {
    for (i=0; i < thiz->all_nodes_num; i++) {
	node = thiz->all_nodes[i];
	if(!node) continue;
	node->failure_node = NULL;
	if(node->matched_patterns_num) {
	   node->matched_patterns_num = !node->outgoing_degree ? 1:0;
	}
    }

    thiz->total_patterns_num = 0;
    ac_automata_traverse_setfailure (thiz, thiz->root, alphas);

    for (i=0; i < thiz->all_nodes_num; i++)
      {
	node = thiz->all_nodes[i];
	if(!node) continue;
	ac_automata_union_matchstrs (node);
	node_sort_edges (node);
	if(max_str_len < node->depth)
		max_str_len = node->depth;
	if(node->matched_patterns_num && !node->outgoing_degree)
		ac_register_match_node(thiz,node);
      }
    thiz->max_str_len = max_str_len;
    thiz->automata_open = 0; /* do not accept patterns any more */
    ndpi_free(alphas);
  }
}

/******************************************************************************
 * FUNCTION: ac_automata_search
 * Search in the input text using the given automata. on match event it will
 * call the call-back function. and the call-back function in turn after doing
 * its job, will return an integer value to ac_automata_search(). 0 value means
 * continue search, and non-0 value means stop search and return to the caller.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * AC_TEXT_t * txt: the input text that must be searched
 * void * param: this parameter will be send to call-back function. it is
 * useful for sending parameter to call-back function from caller function.
 * RETURN VALUE:
 * -1: failed call; automata is not finalized
 *  0: success; continue searching; call-back sent me a 0 value
 *  1: success; stop searching; call-back sent me a non-0 value
 ******************************************************************************/
int ac_automata_search (AC_AUTOMATA_t * thiz, AC_TEXT_t * txt, void * param)
{
  unsigned long position;
  AC_NODE_t *curr;
  AC_NODE_t *next;

  if(thiz->automata_open)
    /* you must call ac_automata_locate_failure() first */
    return -1;

  position = 0;
  curr = thiz->current_node;

  /* This is the main search loop.
   * it must be keep as lightweight as possible. */
  while (position < txt->length)
    {
      if(!(next = node_findbs_next(curr, txt->astring[position])))
	{
	  if(curr->failure_node /* we are not in the root node */)
	    curr = curr->failure_node;
	  else
	    position++;
	}
      else
	{
	  curr = next;
	  position++;
	}

      if(curr->final && next)
	/* We check 'next' to find out if we came here after a alphabet
	 * transition or due to a fail. in second case we should not report
	 * matching because it was reported in previous node */
	{
	  thiz->match.position = position + thiz->base_position;
	  thiz->match.match_num = curr->matched_patterns_num;
	  thiz->match.patterns = curr->matched_patterns;
	  /* we found a match! do call-back */
	  if (thiz->match_callback(&thiz->match, param))
	    return 1;
	}
    }

  /* save status variables */
  thiz->current_node = curr;
  thiz->base_position += position;
  return 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_reset
 * reset the automata and make it ready for doing new search on a new text.
 * when you finished with the input text, you must reset automata state for
 * new input, otherwise it will not work.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 ******************************************************************************/
void ac_automata_reset (AC_AUTOMATA_t * thiz)
{
  thiz->current_node = thiz->root;
  thiz->base_position = 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_release
 * Release all allocated memories to the automata
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 ******************************************************************************/
void ac_automata_release (AC_AUTOMATA_t * thiz)
{
  unsigned int i;
  AC_NODE_t * n;

  for (i=0; i < thiz->all_nodes_num; i++)
    {
      n = thiz->all_nodes[i];
      if(!n) continue;
      node_release(n);
    }
  if(thiz->match_nodes)
	  ndpi_free(thiz->match_nodes);
  ndpi_free(thiz->all_nodes);
  ndpi_free(thiz);
}

/******************************************************************************
 * FUNCTION: ac_automata_display
 * Prints the automata to output in human readable form. it is useful for
 * debugging purpose.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * char repcast: 'n': print AC_REP_t as number, 's': print AC_REP_t as string
 ******************************************************************************/

#ifndef __KERNEL__

void ac_automata_dump(AC_AUTOMATA_t * thiz, char *rstr, size_t rstr_size, char repcast) {
  unsigned int i, j, ip, l;
  struct edge * e;
  struct ac_path *path;
  AC_NODE_t * n;
  AC_PATTERN_t sid;

  path = ndpi_malloc(sizeof(struct ac_path) * (thiz->max_str_len + 2));
  if(!path) return;
  printf("---DUMP- all nodes %u -- max nodes %u- max len. %u - max. num patt %u -%s---\n",
		  thiz->all_nodes_num,thiz->all_nodes_max,thiz->max_str_len,
		  thiz->total_patterns_num,
		  thiz->automata_open ? "open":"ready");
  path[1].n = thiz->root;
  path[1].idx = 0;
  path[1].l = 0;
  ip = 1;
  *rstr = '\0';

  while(ip != 0) {

      n = path[ip].n;

      if (n->matched_patterns_num && !n->outgoing_degree) {
	printf("'%s' %s {",rstr,
			strcmp(n->matched_patterns[0].astring,rstr) ? "NE":"");
	for (j=0; j<n->matched_patterns_num; j++)
	  {
	    sid = n->matched_patterns[j];
	    if(j) printf(", ");
	    switch (repcast)
	      {
	      case 'n':
		printf("%ld %s", sid.rep.number,sid.astring);
		break;
	      case 's':
		printf("%s", sid.rep.stringy);
		break;
	      }
	  }
	printf("}\n");
	ip--;
     	continue;
      }
      l = path[ip].l;

      if( l >= rstr_size-1) {
	ip--;
      	continue;
      }
      for (j = path[ip].idx; j<n->outgoing_degree; j++) {
	  e = &n->outgoing[j];
	  if(e->count) break;
      }
      if(j >= n->outgoing_degree) {
	  ip--;
	  continue;
      }
      path[ip].idx = j+1;
      if(ip > thiz->max_str_len) {
	  ip--;
	  continue;
      }
      ip++;
      rstr[l] = e->alpha;
      rstr[l+1] = '\0';

      path[ip].n = e->next;
      path[ip].idx = 0;
      path[ip].l = l+1;
  }
  printf("---DUMP-END-\n");
  free(path);
}

void ac_automata_display (AC_AUTOMATA_t * thiz, char repcast)
{
  unsigned int i, j, k;
  AC_NODE_t * n;
  struct edge * e;
  AC_PATTERN_t sid;
  
  printf("---DUMP- all nodes %u -- max nodes %u- max len. %u - max. num patt %u -%s---\n",
		  thiz->all_nodes_num,thiz->all_nodes_max,thiz->max_str_len,
		  thiz->total_patterns_num,
		  thiz->automata_open ? "open":"ready");

  for (i=0; i<thiz->all_nodes_num; i++)
    {
      n = thiz->all_nodes[i];
      if(!n) continue;

      if (n->matched_patterns_num) {
	printf("NODE(%3d)/Accepted patterns: {",n->id);
	for (j=0; j<n->matched_patterns_num; j++)
	  {
	    sid = n->matched_patterns[j];
	    if(j) printf(", ");
	    switch (repcast)
	      {
	      case 'n':
		printf("%ld", sid.rep.number);
		break;
	      case 's':
		printf("%s", sid.rep.stringy);
		break;
	      }
	  }
	printf("}\n");
	if(n->outgoing_degree)
		printf("|----fail--------> NODE(%3d)\n",
			n->failure_node ? n->failure_node->id : 0);
      } else {
      	     printf("NODE(%3d)/----fail--------> NODE(%3d)\n",
	     n->id, n->failure_node ? n->failure_node->id : 0);
      }
      
      for (j=0; j<n->outgoing_degree; j++)
	{
	  e = &n->outgoing[j];
	  if(!e->count) continue;

	  printf("         |----(");

	  if(isgraph(e->alpha))
	    printf("%c)--- %3d", e->alpha,e->count);
	  else
	    printf("0x%x) %3d", e->alpha,e->count);
	  if(e->next)
	  	printf("--> NODE(%3d)\n", e->next->id);
	    else
		printf("--> NULL\n");
	}
    }
    printf("---DUMP-END-\n");

}
#else
void ac_automata_display (AC_AUTOMATA_t * thiz, char repcast)
{
}
void ac_automata_dump(AC_AUTOMATA_t * thiz, char *rstr, size_t rstr_size, char repcast) {
}
#endif
/******************************************************************************
 * FUNCTION: ac_automata_register_nodeptr
 * Adds the node pointer to all_nodes.
 ******************************************************************************/
static void ac_automata_register_nodeptr (AC_AUTOMATA_t * thiz, AC_NODE_t * node)
{
  if(thiz->all_nodes_num >= thiz->all_nodes_max)
    {
      thiz->all_nodes = ndpi_realloc(thiz->all_nodes, 
				     thiz->all_nodes_max*sizeof(AC_NODE_t *),
				     (REALLOC_CHUNK_ALLNODES+thiz->all_nodes_max)*sizeof(AC_NODE_t *)
				     );
      thiz->all_nodes_max += REALLOC_CHUNK_ALLNODES;
    }
  node->id = thiz->all_nodes_num;
  thiz->all_nodes[thiz->all_nodes_num++] = node;
}

/******************************************************************************
 * FUNCTION: ac_automata_union_matchstrs
 * Collect accepted patterns of the node. the accepted patterns consist of the
 * node's own accepted pattern plus accepted patterns of its failure node.
 ******************************************************************************/
static void ac_automata_union_matchstrs (AC_NODE_t * node)
{
  unsigned int i;
  AC_NODE_t * m = node;

  while ((m = m->failure_node))
    {
      for (i=0; i < m->matched_patterns_num; i++)
	node_register_matchstr(node, &(m->matched_patterns[i]));

      if (m->final)
	node->final = 1;
    }
  // TODO : sort matched_patterns? is that necessary? I don't think so.
}

/******************************************************************************
 * FUNCTION: ac_automata_set_failure
 * find failure node for the given node.
 ******************************************************************************/
static void ac_automata_set_failure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas)
{
  unsigned int i, j;
  AC_NODE_t * m;

  for (i=1; i < node->depth; i++)
    {
      m = thiz->root;
      for (j=i; j < node->depth && m; j++)
	m = node_find_next (m, alphas[j]);
      if (m)
	{
	  node->failure_node = m;
	  break;
	}
    }
  if (!node->failure_node)
    node->failure_node = thiz->root;
}

/******************************************************************************
 * FUNCTION: ac_automata_traverse_setfailure
 * Traverse all automata nodes using DFS (Depth First Search), meanwhile it set
 * the failure node for every node it passes through. this function must be
 * called after adding last pattern to automata. i.e. after calling this you
 * can not add further pattern to automata.
 ******************************************************************************/
static void ac_automata_traverse_setfailure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas)
{
  unsigned int i;
  AC_NODE_t * next;

  for (i=0; i < node->outgoing_degree; i++)
    {
      if(!node->outgoing[i].count) continue;
      alphas[node->depth] = node->outgoing[i].alpha;
      next = node->outgoing[i].next;

      /* At every node look for its failure node */
      ac_automata_set_failure (thiz, next, alphas);

      /* Recursively call itself to traverse all nodes */
      ac_automata_traverse_setfailure (thiz, next, alphas);
    }
}

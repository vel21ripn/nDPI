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

/* Private function prototype */
static void ac_automata_union_matchstrs (AC_NODE_t * node);
static void ac_automata_set_failure
		(AC_AUTOMATA_t * thiz, AC_NODE_t * node, struct ac_path * path);
static void ac_automata_traverse_setfailure
		(AC_AUTOMATA_t * thiz, AC_NODE_t * node, struct ac_path * path);


static int ac_alloc_path(AC_AUTOMATA_t *thiz, size_t length) {

  if(thiz->ac_path && thiz->ac_path_max < length) {
          ndpi_free(thiz->ac_path);
          thiz->ac_path = NULL;
          thiz->ac_path_max = 0;
  }
  if(!thiz->ac_path) {
        thiz->ac_path = ndpi_malloc(sizeof(struct ac_path) * length);
	if(thiz->ac_path)
        	thiz->ac_path_max = length;
  }
  return thiz->ac_path ? 0:1;
}

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
  if(!thiz) return NULL;
  memset (thiz, 0, sizeof(AC_AUTOMATA_t));
  thiz->root = node_create ();
  thiz->match_callback = mc;
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
      if ((next = node_find_next(n, alpha)))
	{
	  n = next;
	  continue;
	}
      else
	{
	  next = node_create_next(n, alpha);
	  if(!next)
		  return ACERR_ERROR;
	  next->depth = n->depth + 1;
	  n = next;
	}
    }
  if(thiz->max_str_len < patt->length)
     thiz->max_str_len = patt->length;

  if(n->final) {
    patt->rep.number = n->matched_patterns[0].rep.number;
    return ACERR_DUPLICATE_PATTERN;
  }

  n->final = 1;
  node_register_matchstr(n, patt);
  thiz->total_patterns++;

  return ACERR_SUCCESS;
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
  unsigned int ip, j, node_id = 0;
  AC_NODE_t * node;
  struct ac_path *path;

  if(ac_alloc_path(thiz,thiz->max_str_len + 2)) return;

  path  = thiz->ac_path;

  ac_automata_traverse_setfailure (thiz, thiz->root, path);

  path[1].n = thiz->root;
  path[1].idx = 0;
  ip = 1;

  while(ip != 0) {

        node = path[ip].n;
	if(!node->id) {
		node->id = ++node_id;
		ac_automata_union_matchstrs (node);
		node_sort_edges (node);
	}

        j = path[ip].idx;
        if(j >= node->outgoing_degree) {
		ip--;
		continue;
        }
        path[ip].idx = j+1;
        ip++;

        path[ip].n = node->outgoing[j].next;
        path[ip].idx = 0;
  }

    thiz->automata_open = 0; /* do not accept patterns any more */
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

      if(curr->final && next) {
	/* We check 'next' to find out if we came here after a alphabet
	 * transition or due to a fail. in second case we should not report
	 * matching because it was reported in previous node */
	  thiz->match.position = position + thiz->base_position;
	  thiz->match.match_num = curr->matched_patterns_num;
	  thiz->match.patterns = curr->matched_patterns;
	  /* we found a match! do call-back */
	  if (thiz->match_callback(&thiz->match, txt, param))
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
  struct ac_path *path;
  AC_NODE_t *node;
  unsigned int i,ip;

  if(!ac_alloc_path(thiz,thiz->max_str_len + 2)) {

    path  = thiz->ac_path;

    ip = 1;
    path[1].n = thiz->root;
    path[1].idx = 0;

    while(ip) {
          node = path[ip].n;
          i = path[ip].idx;
          if(i >= node->outgoing_degree) {
  		ip--;
                node_release(node);
  		continue;
          }

          path[ip].idx = i+1;
          ip++;
          path[ip].n = node->outgoing[i].next;
          path[ip].idx = 0;
    }
    ndpi_free(thiz->ac_path);
  }
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

  if(ac_alloc_path(thiz,thiz->max_str_len + 2)) return;

  path  = thiz->ac_path;

  if(!path) return;
  printf("---DUMP- all nodes %u - max strlen %u -%s---\n",
		  thiz->all_nodes_num,
		  thiz->max_str_len,
		  thiz->automata_open ? "open":"ready");
  path[1].n = thiz->root;
  path[1].idx = 0;
  path[1].l = 0;
  ip = 1;
  *rstr = '\0';

  while(ip != 0) {

      n = path[ip].n;
      /* for debug */
      if(0 && path[ip].idx)
	    printf("%03d:%d failure %03d\n", n->id,path[ip].idx,
		    n->failure_node ? n->failure_node->id : 0);
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
	  break;
      }
      if(j >= n->outgoing_degree) {
	  ip--;
	  continue;
      }
      path[ip].idx = j+1;
      ip++;
      rstr[l] = e->alpha;
      rstr[l+1] = '\0';

      path[ip].n = e->next;
      path[ip].idx = 0;
      path[ip].l = l+1;
  }
  printf("---DUMP-END-\n");

}

#if 0
void ac_automata_display (AC_AUTOMATA_t * thiz, char repcast)
{
  unsigned int i, j, k;
  AC_NODE_t * n;
  struct edge * e;
  AC_PATTERN_t sid;
  
  printf("---DUMP- all nodes %u -- max nodes %u--%s---\n",
		  thiz->all_nodes_num,thiz->all_nodes_max,
		  thiz->automata_open ? "open":"ready");

  for (i=0; i<thiz->all_nodes_num; i++)
    {
      n = thiz->all_nodes[i];

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

	  printf("         |----(");

	  if(isgraph(e->alpha))
	    printf("%c)--- ", e->alpha);
	  else
	    printf("0x%x) ", e->alpha);
	  if(e->next)
	  	printf("--> NODE(%3d)\n", e->next->id);
	    else
		printf("--> NULL\n");
	}
    }
    printf("---DUMP-END-\n");

}
#endif
#else
//void ac_automata_display (AC_AUTOMATA_t * thiz, char repcast) {
//}
void ac_automata_dump(AC_AUTOMATA_t * thiz, char *rstr, size_t rstr_size, char repcast) {
}
#endif

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
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, struct ac_path * path)
{
  unsigned int i, j;
  AC_NODE_t * m;

  for (i=1; i < node->depth; i++)
    {
      m = thiz->root;
      for (j=i; j < node->depth && m; j++)
	m = node_find_next (m, path[j].l);
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
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, struct ac_path * path)
{
  unsigned int i,ip;
  AC_NODE_t * next;

  ip = 1;
  path[1].n = node;
  path[1].idx = 0;

  while(ip) {
        node = path[ip].n;
        i = path[ip].idx;
        if(i >= node->outgoing_degree) {
		ip--;
		continue;
        }

        path[node->depth].l = node->outgoing[i].alpha;
        next = node->outgoing[i].next;
        /* At every node look for its failure node */
        ac_automata_set_failure (thiz, next, path);

        path[ip].idx = i+1;
        ip++;

        path[ip].n = node->outgoing[i].next;
        path[ip].idx = 0;
  }
}

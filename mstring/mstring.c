#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;

struct mstring_node {
	u_int16_t	n, /* N-char cmp */
				s, /* offset in sbuf */
				e, /* eq    node */
				l, /* left  node */
				r; /* right node */
};
#define MAX_MSTR 64
#define MAX_SBUF 256
struct mstring_parse {
	u_int16_t	smin;		/* min string length */
	u_int16_t	start,last;	/* start node, last node */
	u_int16_t	ri;			/* index of second char */
	char		sbuf[MAX_SBUF];	/* all string */
	u_int16_t	sbuf_len;
	u_int16_t	nstr;		/* number of strings */
	u_int16_t	soffs[MAX_MSTR];/* start offset in sbuf */
	struct mstring_node N[256+MAX_SBUF];
};

struct mstring_source {
	char		*str;
	u_int16_t	value;
};

static void n_p(struct mstring_parse *s,int i) {
struct mstring_node *j;
	j = &s->N[i];
//	if(!j->s) abort();
	if(j->n) { 
		char buf[8];
		if(s->last && j->e > s->last) sprintf(buf,"(%d)",j->e - s->last);
		 else sprintf(buf,"%d",j->e);
		printf("%3d %2d:'%-18.*s' e %4s l %3d r %3d\n",i,j->n,j->n,&s->sbuf[j->s],buf,j->l,j->r);
	} else
		printf("%3d %d\n",i,j->s - s->last);
}
#if 0

static void n_p_a(struct mstring_parse *s,int c) {
	int i;
	printf("---------\n");
	for(i=1;i < c; i++) {
		n_p(s,i);
	}
}

static void f_print(struct mstring_parse *s,int i,char *str,int last) {
struct mstring_node *pt;
	pt = &s->N[i];

//	printf("f_print %d %d %s\n",i,last,str);

	if(pt->l) f_print(s,pt->l,str,last);

	if(pt->e >= last)
		printf("%s%.*s %d\n",str,pt->n,&s->sbuf[pt->s],pt->e - last);
	else {
		if(pt->e) {
		char buf[128];
		snprintf(buf,sizeof(buf),"%s%.*s",str,pt->n,&s->sbuf[pt->s]);
		f_print(s,pt->e,buf,last);
		}
	}
	if(pt->r) f_print(s,pt->r,str,last);
}
#endif

static int f_lr(struct mstring_parse *s,int i,int j) {
	int m;
	if(i >= j) return i;
	m = (i+j)/2;
	if(i < m)
		s->N[m].l = f_lr(s,i,m);

	if(m+1 < j)
		s->N[m].r = f_lr(s,m+1,j);

	return m;
}

static void f_sq(struct mstring_parse *s,int m) {
	struct mstring_node *j,*n;

	j = &s->N[m];
	if( !j->n ) return;
	while(j->e) {
		n = &s->N[j->e];
		if( n->l || n->r || !n->n) break;
		if(j->s + j->n != n->s) {
				printf("f_sq! m %d e %d s+n %d != %d\n",
								m,j->e,j->s + j->n , n->s);
				n_p(s,j->e);
				abort();
		}
		j->n += n->n;
		j->e = n->e;
		n->n = 0;
		n->s = 0;
		n->e = 0;
	}
	if(j->l)
		f_sq(s,j->l);
	if(j->r)
		f_sq(s,j->r);
	if(j->e && j->n && j->e != m)
		f_sq(s,j->e);
}

static void f_eq(struct mstring_parse *s,int m,int p) {
	struct mstring_node *j,*T;
	int l=0,r=0,t,t1;

	j = &s->N[m];
	if( !j->n ) return;

	T = &s->N[0];
	if(j->l) f_eq(s,j->l,m);
	if(j->e) f_eq(s,j->e,m);
	if(j->r) f_eq(s,j->r,m);

	if(m >= s->ri && p >= s->ri) {
//		printf("f_eq: %d p=%d %s\n",m,p);
		t = m;
		while(T[t].l) {
			l++;
			t = T[t].l;
		}
		t = m;
		while(T[t].r) {
			r++;
			t = T[t].r;
		}
		if(abs(l-r) > 1) {
//			printf("f_eq: l %d r %d\n",l,r);
//			n_p(s,m);
			t = m;
			if(l > r) {
				while(l > r && r-l > 1) {
					t1 = T[t].l;
					l--; r++;
					if(T[t1].r) break; /* L+R */
					T[t1].r = t;
					T[t].l = 0;
//					printf("f_eq: L  %d -> %d\n",t,t1);
					t = t1;
				}
			} else {
				while(r > l && r-l > 1) {
					t1 = T[t].r;
					r--; l++;
					if(T[t1].l)  break; /* L+R */
					T[t1].l = t;
					T[t].r = 0;
//					printf("f_eq: R  %d -> %d\n",t,t1);
					t = t1;
				}
			}
			if(t == m) return; /* L+R ? */
			do {
				if(T[p].e == m) {
//						printf("f_eq: p %d m %d e -> %d\n",p,m,t);
						T[p].e = t;
						break;
				}
				if(T[p].l == m) {
//						printf("f_eq: p %d m %d l -> %d\n",p,m,t);
						T[p].l = t;
						break;
				}
				if(T[p].r == m) {
//						printf("f_eq: p %d m %d r -> %d\n",p,m,t);
						T[p].r = t;
						break;
				}
				fprintf(stderr,"%s:%d BUG!\n",__func__,__LINE__);
				abort();
			} while(0);
		}
	}
}

int mstring_compile(struct mstring_source *src,size_t nstr,
				struct mstring_parse *s,
				char *prefix) {
u_int8_t NT[256],c;
struct mstring_node *T,*pt;
char *B;
char *sptr;

int i,l,offs,t,j,I,RI,x,n,k;

memset((char *)s,0,sizeof(*s));

T = &s->N[0];
B = &s->sbuf[0];
I = 256;
for(i=0,offs=1; i < nstr; i++) {
	if(i >= MAX_MSTR) return 1;
	sptr = src[i].str;
	if(!sptr) break;
	l = strlen(sptr);
	if(!l) return 2;

	if(!s->smin || l < s->smin) s->smin = l;

	/* copy string to sbuf in lowercase */
	s->soffs[i] = offs;
	t = 0;

	for(j=0; j < l; j++,offs++) {
		if(offs >= sizeof(s->sbuf)) return 3;
		c = *sptr++;
		if(c >= 'A' && c <= 'Z') c |= 0x20;
		s->sbuf[offs] = c;
//		printf("%d:%c t=%d I=%d\n",offs,c,t,I);
		if(!t) { /* first char in string */
			if(!T[c].n) {
				T[c].n = 1;
				T[c].s = offs;
				T[c].e = I;
				t = I;
			} else {
				t = T[c].e;
			}
			continue;
		}
		if(t >= I) { /* append node */
			I++;
			T[t].n = 1;
			T[t].s = offs;
			T[t].e = I;
			t = I;
			continue;
		}
		x = (int)c - (int)B[T[t].s];
		while(1) {
			if(!x) {
				t = T[t].e;
				break;
			}
			if(x < 0) {
				n = T[t].l;
				if(!n) {
					T[t].l = I+1;
				} else {
					x = (int)c  - (int)B[T[n].s];
					if(x <= 0) {
						t = n;
						continue;
					}
					I++;
					T[I].l = n;
					T[I].e = I+1;
					T[I].n = 1;
					T[I].s = offs;
					T[t].l = I;
					t = ++I;
					break;
				}
			} else {
				n = T[t].r;
				if(!n) {
					T[t].r = I+1;
				} else {
					x = (int)c - (int)B[T[n].s];
					if(x >= 0) {
						t = n;
						continue;
					}
					I++;
					T[I].r = n;
					T[I].e = I+1;
					T[I].n = 1;
					T[I].s = offs;
					T[t].r = I;
					t = ++I;
					break;
				}
			}
			I++;
			T[I].e = I+1;
			T[I].n = 1;
			T[I].s = offs;
			t = ++I;
			break;
		} /* while(1) */
	} /* EOL */
//	printf("EOL t=%d I=%d\n",t,I);
	T[t].n = 0;
	T[t].s = src[i].value;
	if(!T[t].s) T[t].s = i+1;
	I++;
} /* strings */
I++;
s->nstr = i-1;
s->sbuf_len=offs;
s->soffs[i]=offs;
for(c=1,i=1;i < 256; i++) {
	if(T[i].n) {
			T[c++] = T[i];
	}
}
RI = c;
n = 256-c;
// printf("RI=%d n = %d\n",RI,n);

for(i=1 ;i < RI; i++) {
		T[i].e -= n;
}
for(i=256; i < I; i++) {
	T[c] = T[i];
	if(T[c].n) {
		if(T[c].e) T[c].e -= n;
		if(T[c].l) T[c].l -= n;
		if(T[c].r) T[c].r -= n;
	}
	c++;
}
I=c;

s->ri = RI;
s->start = RI >> 1;

if(RI > 2) {
//	printf("f_lr %d\n",RI-1);
	f_lr(s,1,RI-1);
	T[RI-2].r = RI-1;
}

// n_p_a(s,c);

f_sq(s,s->start);

for(i=1,k=1; i < I; i++) {
	if(T[i].s) NT[i]=k++;
}

k = 0;
for(i=1; i < I; i++) {
	if(!T[i].s) continue;
	k = NT[i];
	T[k] = T[i];
	pt = &T[k];

	if(pt->l) pt->l = NT[pt->l];
	if(pt->e) pt->e = NT[pt->e];
	if(pt->r) pt->r = NT[pt->r];
}
I = n = k;

//n_p_a(s,n+1);

//printf("--- RI %d I %d\n",RI,I);

f_eq(s,s->start,0);
//n_p_a(s,n+1);

for(i=RI,j=I; i < j; i++) {
	if(T[i].n) continue;
	while(i < j && !T[j].n) j--;
	if(i >= j) break;
//	printf("%d <-> %d\n",i,j);
	pt = &T[1];
	for(k=1; k <= j; k++,pt++) {
		if(pt->e == j) {
			pt->e = i;
		} else {
			if(pt->e == i) pt->e = j;
		}
		if(pt->l == j) {
			pt->l = i;
		} else {
			if(pt->l == i) pt->l = j;
		}
		if(pt->r == j) {
			pt->r = i;
		} else {
			if(pt->r == i) pt->r = j;
		}
	}
	k = T[i].s;
	T[i] = T[j];
	T[j].l = T[j].r = T[j].e = T[j].n = 0;
	T[j].s = k;
}

while(i <= I) {
	if(!T[i].n) break;
}
s->last = i;
//printf("Last %d\n",i);
for(k=1; k < i; k++) {
	if(T[k].e >= i) {
		j = T[ T[k].e ].s;
		T[k].e = i+j;
	}
}
// n_p_a(s,i);
//f_print(s,s->start,"",i);

printf(
"#ifndef MSTRING_ENGINE\n"
"#define MSTRING_ENGINE\n\n"
"// typedef unsigned char u_int8_t;\n"
"// typedef unsigned short int u_int16_t;\n\n"
"struct mstring_node {\n"
"	u_int16_t	n, /* N-char cmp */\n"
"			s, /* offset in sbuf */\n"
"			l, /* left  node */\n"
"			r; /* right node */\n"
"	u_int16_t	e; /* eq    node or exit code */\n"
"};\n"
"struct mstring_exec {\n"
"	u_int16_t	smin;		/* min string length */\n"
"	u_int16_t	start,last;	/* start node, last node */\n"
"	u_int16_t	sbuf_len;\n"
"	u_int16_t	nstr;		/* number of strings */\n"
"	char		*sbuf;\n"
"	u_int16_t	*soffs;		/* start offset in sbuf */\n"
"	struct mstring_node *N;\n"
"};\n"
"int mstring_find(struct mstring_exec *s,char *str,int l) {\n"
"	int c,i,n,x;\n"
"	char *cs;\n"
"	struct mstring_node *p;\n"
"\n"
"	if(!l) l = strlen(str);\n"
"	if(l < s->smin) return 0;\n"
"	i = s->start;\n"
"	if(!i) return 0;\n"
"\n"
"	p = &s->N[i];\n"
"	n = p->n;\n"
"	cs = &s->sbuf[p->s];\n"
"	while(l > 0 && n > 0) {\n"
"		c = *str++; l--;\n"
"		if(c >= 'A' && c <= 'Z') c |= 0x20;\n"
"		do {\n"
"			x = c  - (int)*cs;\n"
"			if(!x) {\n"
"				cs++; n--;\n"
"				if(n > 0) break;\n"
"				if( p->e >= s->last) return p->e - s->last;\n"
"				i = p->e;\n"
"			} else {\n"
"				if(n != p->n) return 0;\n"
"				i = x < 0 ? p->l : p->r;\n"
"			}\n"
"			if(!i) return 0;\n"
"			p = &s->N[i];\n"
"			n = p->n;\n"
"			cs = &s->sbuf[p->s];\n"
"		} while(x);	\n"
"	}\n"
"	return 0;\n"
"}\n"
"#endif\n"
);
printf("/* Source %s\n  mstring %s ",prefix,prefix);

j = 12+strlen(prefix);

for(i=0; i <= s->nstr; i++) {
	k = s->soffs[i+1]-s->soffs[i];
	if(j + k+3 > 68 && k < 68-3) {
			printf("\\\n\t");
			j = 8;
	}
	printf("\"%.*s\" ", k, &s->sbuf[s->soffs[i]]);
	j += k+3;
}
printf("\n\n");
for(i=0; i <= s->nstr; i++) {
	printf("\t\"%.*s\",%d\n",
				s->soffs[i+1]-s->soffs[i],
				&s->sbuf[s->soffs[i]],
				src[i].value ? src[i].value:i+1);
}
printf(" */\n");
printf("static char mstring_sbuf_%s[] = \"#%.*s\";\n",prefix,s->sbuf_len,&s->sbuf[1]);
printf("static u_int16_t mstring_soffs_%s[%d] = {\n\t0,",prefix,s->nstr+3);
for(k=0; k <= s->nstr+1; k++) {
	printf("%d%c",s->soffs[k],k == s->nstr+1 ? ' ':',');
}
printf("\n};\n");
printf("static struct mstring_node mstring_node_%s[%d] = {\n\t{0,},\n",prefix,s->last+1);

for(k=1; k < s->last; k++) {
	printf("\t{ .n = %d, .s = %d, .l = %d, .r = %d, .e = %d }%c\n",
		T[k].n, T[k].s, T[k].l, T[k].r, T[k].e,
		k == s->last-1 ? ' ':',');
}
printf("};\n");
printf("struct mstring_exec mstring_data_%s = {\n"
		"\t.smin = %d,\n"
		"\t.start = %d, .last = %d,\n"
		"\t.sbuf_len = %d,\n" 
		"\t.sbuf = &mstring_sbuf_%s[0],\n"
		"\t.soffs = mstring_soffs_%s,\n"
		"\t.N = &mstring_node_%s[0]\n};\n",
		prefix, s->smin,
		s->start, s->last,
		s->sbuf_len,
		prefix,prefix,prefix);

return 0;
}

int mstring_find(struct mstring_parse *s,char *str) {
	int c,l,i,n,x;
	char *cs;

	l = strlen(str);
	if(l < s->smin) return 0;
	i = s->start;

	n = s->N[i].n;
	cs = &s->sbuf[s->N[i].s];

	while(l > 0 && n > 0) {
		c = *str++; l--;
		if(c >= 'A' && c <= 'Z') c |= 0x20;
		while(1) {	
			x = c  - (int)*cs;
			if(!x) {
				cs++; n--;
				if(n > 0) break;
				if(s->N[i].e >= s->last) return s->N[i].e - s->last;
				i = s->N[i].e;
			} else {
				if(n != s->N[i].n) return 0;
				i = x < 0 ? s->N[i].l : s->N[i].r;
			}
			if(!i) return 0;
			n = s->N[i].n;
			cs = &s->sbuf[s->N[i].s];
			if(!x) break;
		}	
	}
	return 0;
}

struct mstring_source A[]= {
		{"Content-Encoding:",0},
		{"Content-Encoder:",0},
		{"Content-Mime:",0},
		{"Content-Length:",0},
		{"Content-Xscope:",0},
		{"Content-Type:",0},
		{"Cookie:",0},
		{"Host:",0},
		{"Referer:",0},
		{"Server:",0},
		{"Transfer-Encoding:",0},
		{"User-agent:",0},
		{"X-Forwarded-For:",0},
		{"X-Session-Type:",0},
		{"YHost:",0}
};


int main(int argc,char **argv) {
int i;
struct mstring_parse s;

if(argc > 3) {
	struct mstring_source *S = calloc(argc-1,sizeof(struct mstring_source));
	for(i=2; i < argc; i++) {
		S[i-2].str = argv[i];
		S[i-2].value = 0;
		fprintf(stderr,"%d %s\n",i-1,argv[i]);
	}
	i = mstring_compile(S,i-1,&s,argv[1]);
	if(i)
		fprintf(stderr,"error: mstring_compile:%d\n",i);
	exit(i != 0);
}
fprintf(stderr,"%s prefix word1 word2 ....\n",argv[0]);

#if 0
i = argv[1] ? atoi(argv[1]) : 1;
if(i > sizeof(A)/sizeof(A[0])) i = sizeof(A)/sizeof(A[0]);
printf("//ret %d\n",mstring_compile(A,i,&s,"hdr")); //sizeof(A)/sizeof(A[0])));

if(argv[2]) {
	printf("ret %d for %s\n",mstring_find(&s,argv[2]),argv[2]);
}
#endif

return 1;

}


/* vim: set ts=4: */



#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "ndpi_config.h"
#include "ndpi_protocol_ids.h"

#include "ndpi_api.h"

#include "third_party/src/ndpi_patricia.c"

#define _P(a) [a] = #a

const char *proto_def[NDPI_LAST_IMPLEMENTED_PROTOCOL+1] = {

_P(NDPI_PROTOCOL_UNKNOWN),
_P(NDPI_PROTOCOL_FTP_CONTROL),
_P(NDPI_PROTOCOL_MAIL_POP),
_P(NDPI_PROTOCOL_MAIL_SMTP),
_P(NDPI_PROTOCOL_MAIL_IMAP),
_P(NDPI_PROTOCOL_DNS),
_P(NDPI_PROTOCOL_IPP),
_P(NDPI_PROTOCOL_HTTP),
_P(NDPI_PROTOCOL_MDNS),
_P(NDPI_PROTOCOL_NTP),
_P(NDPI_PROTOCOL_NETBIOS),
_P(NDPI_PROTOCOL_NFS),
_P(NDPI_PROTOCOL_SSDP),
_P(NDPI_PROTOCOL_BGP),
_P(NDPI_PROTOCOL_SNMP),
_P(NDPI_PROTOCOL_XDMCP),
_P(NDPI_PROTOCOL_SMB),
_P(NDPI_PROTOCOL_SYSLOG),
_P(NDPI_PROTOCOL_DHCP),
_P(NDPI_PROTOCOL_POSTGRES),
_P(NDPI_PROTOCOL_MYSQL),
_P(NDPI_PROTOCOL_HOTMAIL),
_P(NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK),
_P(NDPI_PROTOCOL_MAIL_POPS),
_P(NDPI_PROTOCOL_APPLEJUICE),
_P(NDPI_PROTOCOL_DIRECTCONNECT),
_P(NDPI_PROTOCOL_SOCRATES),
_P(NDPI_PROTOCOL_COAP),
_P(NDPI_PROTOCOL_VMWARE),
_P(NDPI_PROTOCOL_MAIL_SMTPS),
_P(NDPI_PROTOCOL_FILETOPIA),
_P(NDPI_PROTOCOL_UBNTAC2),
_P(NDPI_PROTOCOL_KONTIKI),
_P(NDPI_PROTOCOL_OPENFT),
_P(NDPI_PROTOCOL_FASTTRACK),
_P(NDPI_PROTOCOL_GNUTELLA),
_P(NDPI_PROTOCOL_EDONKEY),
_P(NDPI_PROTOCOL_BITTORRENT),
_P(NDPI_PROTOCOL_EPP),
_P(NDPI_CONTENT_AVI),
_P(NDPI_CONTENT_FLASH),
_P(NDPI_CONTENT_OGG),
_P(NDPI_CONTENT_MPEG),
_P(NDPI_CONTENT_QUICKTIME),
_P(NDPI_CONTENT_REALMEDIA),
_P(NDPI_CONTENT_WINDOWSMEDIA),
_P(NDPI_CONTENT_MMS),
_P(NDPI_PROTOCOL_XBOX),
_P(NDPI_PROTOCOL_QQ),
_P(NDPI_PROTOCOL_MOVE),
_P(NDPI_PROTOCOL_RTSP),
_P(NDPI_PROTOCOL_MAIL_IMAPS),
_P(NDPI_PROTOCOL_ICECAST),
_P(NDPI_PROTOCOL_PPLIVE),
_P(NDPI_PROTOCOL_PPSTREAM),
_P(NDPI_PROTOCOL_ZATTOO),
_P(NDPI_PROTOCOL_SHOUTCAST),
_P(NDPI_PROTOCOL_SOPCAST),
_P(NDPI_PROTOCOL_TVANTS),
_P(NDPI_PROTOCOL_TVUPLAYER),
_P(NDPI_PROTOCOL_HTTP_DOWNLOAD),
_P(NDPI_PROTOCOL_QQLIVE),
_P(NDPI_PROTOCOL_THUNDER),
_P(NDPI_PROTOCOL_SOULSEEK),
_P(NDPI_PROTOCOL_SSL_NO_CERT),
_P(NDPI_PROTOCOL_IRC),
_P(NDPI_PROTOCOL_AYIYA),
_P(NDPI_PROTOCOL_UNENCRYPTED_JABBER),
_P(NDPI_PROTOCOL_MSN),
_P(NDPI_PROTOCOL_OSCAR),
_P(NDPI_PROTOCOL_YAHOO),
_P(NDPI_PROTOCOL_BATTLEFIELD),
_P(NDPI_PROTOCOL_GOOGLE_PLUS),
_P(NDPI_PROTOCOL_IP_VRRP),
_P(NDPI_PROTOCOL_STEAM),
_P(NDPI_PROTOCOL_HALFLIFE2),
_P(NDPI_PROTOCOL_WORLDOFWARCRAFT),
_P(NDPI_PROTOCOL_TELNET),
_P(NDPI_PROTOCOL_STUN),
_P(NDPI_PROTOCOL_IP_IPSEC),
_P(NDPI_PROTOCOL_IP_GRE),
_P(NDPI_PROTOCOL_IP_ICMP),
_P(NDPI_PROTOCOL_IP_IGMP),
_P(NDPI_PROTOCOL_IP_EGP),
_P(NDPI_PROTOCOL_IP_SCTP),
_P(NDPI_PROTOCOL_IP_OSPF),
_P(NDPI_PROTOCOL_IP_IP_IN_IP),
_P(NDPI_PROTOCOL_RTP),
_P(NDPI_PROTOCOL_RDP),
_P(NDPI_PROTOCOL_VNC),
_P(NDPI_PROTOCOL_PCANYWHERE),
_P(NDPI_PROTOCOL_SSL),
_P(NDPI_PROTOCOL_SSH),
_P(NDPI_PROTOCOL_USENET),
_P(NDPI_PROTOCOL_MGCP),
_P(NDPI_PROTOCOL_IAX),
_P(NDPI_PROTOCOL_TFTP),
_P(NDPI_PROTOCOL_AFP),
_P(NDPI_PROTOCOL_STEALTHNET),
_P(NDPI_PROTOCOL_AIMINI),
_P(NDPI_PROTOCOL_SIP),
_P(NDPI_PROTOCOL_TRUPHONE),
_P(NDPI_PROTOCOL_IP_ICMPV6),
_P(NDPI_PROTOCOL_DHCPV6),
_P(NDPI_PROTOCOL_ARMAGETRON),
_P(NDPI_PROTOCOL_CROSSFIRE),
_P(NDPI_PROTOCOL_DOFUS),
_P(NDPI_PROTOCOL_FIESTA),
_P(NDPI_PROTOCOL_FLORENSIA),
_P(NDPI_PROTOCOL_GUILDWARS),
_P(NDPI_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC),
_P(NDPI_PROTOCOL_KERBEROS),
_P(NDPI_PROTOCOL_LDAP),
_P(NDPI_PROTOCOL_MAPLESTORY),
_P(NDPI_PROTOCOL_MSSQL_TDS),
_P(NDPI_PROTOCOL_PPTP),
_P(NDPI_PROTOCOL_WARCRAFT3),
_P(NDPI_PROTOCOL_WORLD_OF_KUNG_FU),
_P(NDPI_PROTOCOL_SLACK),
_P(NDPI_PROTOCOL_FACEBOOK),
_P(NDPI_PROTOCOL_TWITTER),
_P(NDPI_PROTOCOL_DROPBOX),
_P(NDPI_PROTOCOL_GMAIL),
_P(NDPI_PROTOCOL_GOOGLE_MAPS),
_P(NDPI_PROTOCOL_YOUTUBE),
_P(NDPI_PROTOCOL_SKYPE),
_P(NDPI_PROTOCOL_GOOGLE),
_P(NDPI_PROTOCOL_DCERPC),
_P(NDPI_PROTOCOL_NETFLOW),
_P(NDPI_PROTOCOL_SFLOW),
_P(NDPI_PROTOCOL_HTTP_CONNECT),
_P(NDPI_PROTOCOL_HTTP_PROXY),
_P(NDPI_PROTOCOL_CITRIX),
_P(NDPI_PROTOCOL_NETFLIX),
_P(NDPI_PROTOCOL_LASTFM),
_P(NDPI_PROTOCOL_WAZE),
_P(NDPI_PROTOCOL_YOUTUBE_UPLOAD),
_P(NDPI_PROTOCOL_ICQ),
_P(NDPI_PROTOCOL_CHECKMK),
_P(NDPI_PROTOCOL_CITRIX_ONLINE),
_P(NDPI_PROTOCOL_APPLE),
_P(NDPI_PROTOCOL_WEBEX),
_P(NDPI_PROTOCOL_WHATSAPP),
_P(NDPI_PROTOCOL_APPLE_ICLOUD),
_P(NDPI_PROTOCOL_VIBER),
_P(NDPI_PROTOCOL_APPLE_ITUNES),
_P(NDPI_PROTOCOL_RADIUS),
_P(NDPI_PROTOCOL_WINDOWS_UPDATE),
_P(NDPI_PROTOCOL_TEAMVIEWER),
_P(NDPI_PROTOCOL_TUENTI),
_P(NDPI_PROTOCOL_LOTUS_NOTES),
_P(NDPI_PROTOCOL_SAP),
_P(NDPI_PROTOCOL_GTP),
_P(NDPI_PROTOCOL_UPNP),
_P(NDPI_PROTOCOL_LLMNR),
_P(NDPI_PROTOCOL_REMOTE_SCAN),
_P(NDPI_PROTOCOL_SPOTIFY),
_P(NDPI_CONTENT_WEBM),
_P(NDPI_PROTOCOL_H323),
_P(NDPI_PROTOCOL_OPENVPN),
_P(NDPI_PROTOCOL_NOE),
_P(NDPI_PROTOCOL_CISCOVPN),
_P(NDPI_PROTOCOL_TEAMSPEAK),
_P(NDPI_PROTOCOL_TOR),
_P(NDPI_PROTOCOL_SKINNY),
_P(NDPI_PROTOCOL_RTCP),
_P(NDPI_PROTOCOL_RSYNC),
_P(NDPI_PROTOCOL_ORACLE),
_P(NDPI_PROTOCOL_CORBA),
_P(NDPI_PROTOCOL_UBUNTUONE),
_P(NDPI_PROTOCOL_WHOIS_DAS),
_P(NDPI_PROTOCOL_COLLECTD),
_P(NDPI_PROTOCOL_SOCKS),
_P(NDPI_PROTOCOL_NINTENDO),
_P(NDPI_PROTOCOL_RTMP),
_P(NDPI_PROTOCOL_FTP_DATA),
_P(NDPI_PROTOCOL_WIKIPEDIA),
_P(NDPI_PROTOCOL_ZMQ),
_P(NDPI_PROTOCOL_AMAZON),
_P(NDPI_PROTOCOL_EBAY),
_P(NDPI_PROTOCOL_CNN),
_P(NDPI_PROTOCOL_MEGACO),
_P(NDPI_PROTOCOL_REDIS),
_P(NDPI_PROTOCOL_PANDO),
_P(NDPI_PROTOCOL_VHUA),
_P(NDPI_PROTOCOL_TELEGRAM),
_P(NDPI_PROTOCOL_VEVO),
_P(NDPI_PROTOCOL_PANDORA),
_P(NDPI_PROTOCOL_QUIC),
_P(NDPI_PROTOCOL_WHATSAPP_VOICE),
_P(NDPI_PROTOCOL_EAQ),
_P(NDPI_PROTOCOL_OOKLA),
_P(NDPI_PROTOCOL_AMQP),
_P(NDPI_PROTOCOL_KAKAOTALK),
_P(NDPI_PROTOCOL_KAKAOTALK_VOICE),
_P(NDPI_PROTOCOL_TWITCH),
_P(NDPI_PROTOCOL_QUICKPLAY),
_P(NDPI_PROTOCOL_WECHAT),
_P(NDPI_PROTOCOL_MPEGTS),
_P(NDPI_PROTOCOL_SNAPCHAT),
_P(NDPI_PROTOCOL_SINA),
_P(NDPI_PROTOCOL_HANGOUT),
_P(NDPI_PROTOCOL_IFLIX),
_P(NDPI_PROTOCOL_GITHUB),
_P(NDPI_PROTOCOL_BJNP),
_P(NDPI_PROTOCOL_1KXUN),
_P(NDPI_PROTOCOL_IQIYI),
_P(NDPI_PROTOCOL_SMPP),
_P(NDPI_PROTOCOL_DNSCRYPT),
_P(NDPI_PROTOCOL_TINC),
_P(NDPI_PROTOCOL_DEEZER),
_P(NDPI_PROTOCOL_INSTAGRAM),
_P(NDPI_PROTOCOL_MICROSOFT),
_P(NDPI_PROTOCOL_STARCRAFT),
_P(NDPI_PROTOCOL_TEREDO),
_P(NDPI_PROTOCOL_HOTSPOT_SHIELD),
_P(NDPI_PROTOCOL_HEP),
_P(NDPI_PROTOCOL_GOOGLE_DRIVE),
_P(NDPI_PROTOCOL_OCS),
_P(NDPI_PROTOCOL_OFFICE_365),
_P(NDPI_PROTOCOL_CLOUDFLARE),
_P(NDPI_PROTOCOL_MS_ONE_DRIVE),
_P(NDPI_PROTOCOL_MQTT),
_P(NDPI_PROTOCOL_RX),
_P(NDPI_PROTOCOL_APPLESTORE),
_P(NDPI_PROTOCOL_OPENDNS),
_P(NDPI_PROTOCOL_GIT),
_P(NDPI_PROTOCOL_DRDA),
_P(NDPI_PROTOCOL_PLAYSTORE),
_P(NDPI_PROTOCOL_SOMEIP),
_P(NDPI_PROTOCOL_FIX),
_P(NDPI_PROTOCOL_PLAYSTATION),
_P(NDPI_PROTOCOL_PASTEBIN),
_P(NDPI_PROTOCOL_LINKEDIN),
_P(NDPI_PROTOCOL_SOUNDCLOUD),
_P(NDPI_PROTOCOL_CSGO),
_P(NDPI_PROTOCOL_LISP),
_P(NDPI_PROTOCOL_DIAMETER),
_P(NDPI_PROTOCOL_APPLE_PUSH),
_P(NDPI_PROTOCOL_GOOGLE_SERVICES)
};


struct net_cidr {
	struct in_addr a;
	uint16_t masklen;
};

struct net_cidr_list {
	size_t		alloc,use;
	char		comments[512];
	struct net_cidr addr[0];
} *net_cidr_list[NDPI_LAST_IMPLEMENTED_PROTOCOL+1];

const char *get_proto_by_id(uint16_t proto) {
const char *s;
if(proto > NDPI_LAST_IMPLEMENTED_PROTOCOL) return "UNKNOWN";
s = proto_def[proto];
s += 12;
if(*s != '_') s++;
if(*s != '_') abort();
s++;
return s;
}

uint16_t get_proto_by_name(const char *name) {
const char *s;
int i;
if(!name || !*name) return NDPI_PROTOCOL_UNKNOWN;
for(i=0; i < sizeof(proto_def)/sizeof(proto_def[0]); i++) {
	s = proto_def[i];
	s += 12;
	if(*s != '_') s++;
	if(*s != '_') abort();
	s++;
	if(!strcasecmp(s,name)) return i;
}
return NDPI_PROTOCOL_UNKNOWN;
}

void *ndpi_calloc(size_t nmemb, size_t size) {
	return calloc(nmemb,size);
}
void ndpi_free(void *buf) {
	free(buf);
}


void add_net_cidr_proto(struct in_addr *addr,uint16_t masklen, uint16_t proto) {
struct net_cidr_list *nl;

if(proto > NDPI_LAST_IMPLEMENTED_PROTOCOL) abort();
nl = net_cidr_list[proto];
if(!nl) {
	nl = malloc(sizeof(struct net_cidr_list) + 32 * sizeof(struct net_cidr));
	if(!nl) abort();
	net_cidr_list[proto] = nl;
	bzero((char *)nl,sizeof(struct net_cidr_list) + 32 * sizeof(struct net_cidr));
	nl->alloc = 32;
}
if(nl->use == nl->alloc) {
	size_t n = nl->alloc + 32;
	nl = realloc(nl,sizeof(struct net_cidr_list) + n * sizeof(struct net_cidr));
	if(!nl) abort();
	net_cidr_list[proto] = nl;
	nl->alloc = n;
}
if(addr) {
	nl->addr[nl->use].a = *addr;
	nl->addr[nl->use].masklen = masklen;
	nl->use++;
}
}

static void free_ptree_data(void *data) { ; };

static char *prefix_str(prefix_t *px, int proto,char *lbuf,size_t bufsize) {
char ibuf[64];
int k;
	lbuf[0] = 0;
	inet_ntop(px->family,(void *)&px->add,ibuf,sizeof(ibuf)-1);
	k = strlen(ibuf);
	if((px->family == AF_INET  && px->bitlen < 32 ) ||
	   (px->family == AF_INET6 && px->bitlen < 128 ))
		snprintf(&ibuf[k],sizeof(ibuf)-k,"/%d",px->bitlen);
	if(proto < 0)
		snprintf(lbuf,bufsize,"%s",ibuf);
	else
		snprintf(lbuf,bufsize,"%-18s %s",ibuf,
			proto > NDPI_LAST_IMPLEMENTED_PROTOCOL ?
				"unknown":get_proto_by_id(proto));
	return lbuf;
}

static void list_ptree(patricia_tree_t *pt)
{
	patricia_node_t *Xstack[PATRICIA_MAXBITS+1], **Xsp, *node;

	Xsp = &Xstack[0];
	node = pt->head;
	while (node) {
	    if (node->prefix) {
		add_net_cidr_proto(&node->prefix->add.sin,node->prefix->bitlen,node->value.user_value);
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
}

/* 0: bad format
 * 1: comment
 * 2: word
 * 3: list
 */

int parse_line(char *l,int *sp, char *word,size_t wlen,char **optarg) {

char *s = l,*sw,*dlm;

  *sp = 0;
  *word = '\0';
  *optarg = NULL;

  dlm = strchr(s,'\r');
  if(dlm) *dlm = '\0';
  dlm = strchr(s,'\n');
  if(dlm) *dlm = '\0';

  while(*s && (*s == ' ' || *s == '\t')) { (*sp) += *s == ' ' ? 1:8; s++; }
  if(!*s) return 1;
  if(*s == '#') return 1;
  sw = s;
  bzero(word,wlen);
  if(*s == '-') { // element of list
	s++;
	while(*s && (*s == ' ' || *s == '\t')) s++;
	if(!*s) return 1;
	strncpy(word,s,wlen);
	return 3;
  }
  dlm = strchr(sw,':');
  if(!dlm) return 0;
  strncpy(word,s,wlen < (dlm - sw) ? wlen : dlm - sw);
  if(strchr(word,' ') || strchr(word,'\t')) return 0;
  dlm++;
  while(*dlm && (*dlm == ' ' || *dlm == '\t')) dlm++;
  *optarg = *dlm ? dlm : NULL;
  return 2;
}


int is_protocol(char *line,uint16_t *protocol) {

    *protocol = get_proto_by_name(line);

    return *protocol != NDPI_PROTOCOL_UNKNOWN;
}

int main(int argc,char **argv) {

  struct in_addr pin;
  patricia_node_t *node;
  patricia_tree_t *ptree;
  prefix_t prefix;
  FILE *fd;
  int i,line,err,nsp,psp;
  uint16_t protocol;
  char word[32],lastword[32],*optarg;
 
  struct net_cidr_list *pnl = NULL;

  if(argc < 2 || !argv[1]) abort();

  ptree = ndpi_New_Patricia(32 /* IPv4 */);
  if(!ptree) abort();


  fd = fopen(argv[1],"r");
  if(!fd) abort();
  line = 0;
  psp = 0;
  while(!feof(fd)) {
	char lbuf[256],*s;
	if(!(s = fgets(lbuf,sizeof(lbuf),fd))) {
		break;
	}
	line++;
	nsp = 0;

	optarg = NULL;
	err = parse_line(s,&nsp,word,sizeof(word)-1,&optarg);

	if(err == 0) {
		fprintf(stderr,"Error: Invalid line %d: '%s'\n",line,s);
		exit(1);
	}
	if(err == 1) continue;

//	printf("%s\n  res:%d sp %d word '%s'\n",s,err,nsp,word);

	if( err == 2 ) {
		if(!nsp) {
			if(!is_protocol(word,&protocol)) {
				fprintf(stderr,"Error: unknown protocol '%s' line %d: '%s'\n",
						word,line,s);
				exit(1);
			}
			add_net_cidr_proto(NULL,0,protocol);
			pnl = net_cidr_list[protocol];
//			printf("Start protocol %s\n",word);
			psp = 0;
			lastword[0] = '\0';
			continue;
		}
		if(psp && psp != nsp) {
			fprintf(stderr,"Invalid line %d: '%s'\n",line,s);
			exit(1);
		}
		psp = nsp;

		if(!strcmp(word,"id")) {
//			printf("ID protocol %s optarg %s\n",word,optarg);
			continue;
		}
		if(!strcmp(word,"source")) {
//			printf("Source %s optarg %s\n",word,optarg);
			strncpy(lastword,word,sizeof(lastword));
			if(optarg)
				strncat(pnl->comments,optarg,sizeof(pnl->comments));
			continue;
		}
		if(!strcmp(word,"ip")) {
			if(optarg) {
				fprintf(stderr,"Invalid line %d: '%s'\n",line,s);
				exit(1);
			}
//			printf("IP list start\n");
			strncpy(lastword,word,sizeof(lastword));
			continue;
		}
		fprintf(stderr,"Invalid line %d: '%s'\n",line,s);
		exit(1);
	}
	if( err == 3 ) {
		if(!psp || nsp <= psp) {
			fprintf(stderr,"Invalid list line %d: '%s'\n",line,s);
			exit(1);
		}
		if(!strcmp(lastword,"ip")) {
			char *nm = strchr(word,'/');
			int ml = nm ? atoi(nm+1) : 32;
			if(nm) *nm = 0;
			if(!inet_aton(word,&pin)) {
				fprintf(stderr,"Invalid ip in line %d: '%s'\n",line,s);
				exit(1);
			}
			pin.s_addr &= htonl(0xfffffffful << (32 - ml));

			memset((char *)&prefix, 0, sizeof(prefix_t));
			prefix.add.sin.s_addr = pin.s_addr;
			prefix.family = AF_INET;
			prefix.bitlen = ml;
			prefix.ref_count = 0;

			node = ndpi_patricia_search_best(ptree, &prefix);
#if 0
			if(node && node->prefix && protocol != node->value.user_value) {
			    char lbuf[128],lbuf2[128];

			    printf("#%-32s\t-> %s\n",
				prefix_str(&prefix,protocol,lbuf2,sizeof lbuf2),
				prefix_str(node->prefix,node->value.user_value,lbuf,sizeof lbuf)
				);
			}
#endif
			node = ndpi_patricia_lookup(ptree, &prefix);
			if(node) 
			  node->value.user_value = protocol;

//			printf("\t add ip %s to protocol %s\n",word,get_proto_by_id(protocol));
			continue;
		}
		if(!strcmp(lastword,"source")) {
			if(pnl->comments[0]) {
				strncat(pnl->comments,"\n    ",sizeof(pnl->comments));
//			} else {
//				strncat(pnl->comments," ",sizeof(pnl->comments));
			}
			strncat(pnl->comments,word,sizeof(pnl->comments));
//			printf("\t add comment %s to protocol %s\n",word,get_proto_by_id(protocol));
			continue;
		}
		fprintf(stderr,"Invalid list word '%s'\n",lastword);
		exit(1);
	}
	printf("err = %d\n",err);
	abort();
  }
  
  list_ptree(ptree);

  ndpi_Destroy_Patricia(ptree, free_ptree_data);
 
  printf("/*\n\n\tDon't edit this file!\n\n\tsource file: %s\n\n */\n\n",argv[1]);
  printf("ndpi_network host_protocol_list[] = {\n");

  for(i=0; i <= NDPI_LAST_IMPLEMENTED_PROTOCOL; i++) {
	char lbuf[128];
	struct net_cidr_list *nl = net_cidr_list[i];
	int l,mg;
	if(!nl) continue;
        
	const  char *pname = get_proto_by_id(i);

	if(nl->comments[0])
		printf("  /*\n    %s\n   */\n",nl->comments);
	else 
		printf("  /*\n    %s\n   */\n",pname);
	do {
	    mg = 0;
	    for(l=0; l < nl->use; l++) {
		if(l+1 < nl->use) {
			if(nl->addr[l].masklen > 0 &&
			   nl->addr[l].masklen == nl->addr[l+1].masklen) {
				uint32_t a = htonl(nl->addr[l].a.s_addr);
				uint32_t m = 0xfffffffful << (32 - nl->addr[l].masklen);
				if( (a & ~(m << 1)) == 0 &&
				     a + (~m + 1) == htonl(nl->addr[l+1].a.s_addr)) {
					nl->addr[l].masklen--;
					for(int l2 = l+1; l2+1 < nl->use; l2++)
						nl->addr[l2] = nl->addr[l2+1];
					nl->use--;
					mg++;
				}
			}
		}
	    }
	} while(mg);

	for(l=0; l < nl->use; l++) {
  		prefix_t prefix1;
		memset((char *)&prefix1, 0, sizeof(prefix_t));
		prefix1.add.sin = nl->addr[l].a;
		prefix1.family = AF_INET;
		prefix1.bitlen = nl->addr[l].masklen;
		prefix1.ref_count = 0;
		printf("  { 0x%08X, %d , %s /* %-18s */  },\n",
				htonl(prefix1.add.sin.s_addr), nl->addr[l].masklen,
				proto_def[i], prefix_str(&prefix1,-1,lbuf,sizeof lbuf)
				);
	}
  }
  printf("  { 0x0, 0, 0 }\n};\n");

  return(0);
}

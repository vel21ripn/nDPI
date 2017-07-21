/*
 * 
 *
 * Copyright (C) 2016 Vitaly Lavrov
 *
 */

#include "ndpi_api.h"


#ifdef NDPI_PROTOCOL_CSGO

#ifndef __KERNEL__
static void dump_hex(const uint8_t *pl, uint32_t len, int max) {
int i,l;
l = len;
if(max < l) l = max;
for(i=0; i < l; i+=2) {
  if(!(i & 0xf)) fprintf(stderr,"%03x: ",i);
  fprintf(stderr,"%04x%c",htons(*(uint16_t *)(pl+i)),(i & 0xf) == 0xe ? '\n':' ');
}
if(i & 0xf) fprintf(stderr,"\n");
}
#endif

void ndpi_search_csgo(struct ndpi_detection_module_struct* ndpi_struct,
                         struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &flow->packet;
#ifndef __KERNEL__
  if(0) {
    NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
           "CSGO: search packet %s len %d %d:%d num_retries_bytes %d pac_cnt %d dir %d\n",
           packet->tcp ? "tcp" : ( packet->udp ? "udp" : "x"),
           packet->payload_packet_len,
           htons(packet->tcp ? packet->tcp->source: packet->udp ? packet->udp->source:0),
           htons(packet->tcp ? packet->tcp->dest: packet->udp ? packet->udp->dest:0),
           packet->num_retried_bytes,
           flow->packet_counter,packet->packet_direction);
    dump_hex((u_int8_t *)packet->payload,packet->payload_packet_len,128);
  }
#endif

  if (packet->udp != NULL) {
	uint32_t w = htonl(get_u_int32_t(packet->payload,0));
	NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG, "CSGO: word %08x\n",w);

	if (!flow->csgo_state && packet->payload_packet_len == 23 && w == 0xfffffffful) {
	    if(!memcmp(packet->payload+5,"connect0x",9)) {
		NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
			 "found csgo connect0x\n");
		flow->csgo_state++;
		memcpy(flow->csgo_strid,packet->payload+5,18);
		return;
	    }
	}
	if (flow->csgo_state == 1 && packet->payload_packet_len >= 42 && w == 0xfffffffful) {
	    if(!memcmp(packet->payload+24,flow->csgo_strid,18)) {
		NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
			 "found csgo connect0x reply\n");
		flow->csgo_state++;
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
		return;
	    }

	}

	if (packet->payload_packet_len == 8 && 
			( w == 0x3a180000 || w == 0x39180000) ) {
		NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
			 "found csgo udp 8b.\n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
		return;
	}

	if (packet->payload_packet_len >= 36 && w == 0x56533031ul) {
		NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
			 "found csgo udp.\n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	if (packet->payload_packet_len >= 36 && w == 0x01007364) {
		uint32_t w2 = htonl(get_u_int32_t(packet->payload,4));
		if(w2 == 0x70696e67) {
			NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
				 "found csgo udp ping\n");
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
			return;
		}
	}
	if(flow->csgo_s2 < 3 && (w & 0xffff0000ul)  == 0x0d1d0000) {
	  uint32_t w2 = get_u_int32_t(packet->payload,2);
	  if (packet->payload_packet_len == 13) {
		if(!flow->csgo_s2) {
			flow->csgo_id2 = w2;
			flow->csgo_s2 = 1;
			NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
				 "found csgo udp 0d1d step1\n");
			return;
		}
		if(flow->csgo_s2 == 1 && flow->csgo_id2 == w2) {
			NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
				 "found csgo udp 0d1d step1 DUP\n");
			return;
		}
		flow->csgo_s2 = 3;
		return;
	  }
	  if (packet->payload_packet_len == 15) {
		if(flow->csgo_s2 == 1 && flow->csgo_id2 == w2) {
			NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
				 "found csgo udp 0d1d\n");
			ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
			return;
		}
	  }
	  flow->csgo_s2 = 3;
	}

	if (packet->payload_packet_len >= 140 && 
	    ( w == 0x02124c6c || w == 0x02125c6c) &&
	    !memcmp(&packet->payload[3],"lta\000mob\000tpc\000bhj\000bxd\000tae\000urg\000gkh\000",32)) {
		NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
			 "found csgo dictionary udp.\n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
	if (packet->payload_packet_len >= 33 &&
	    packet->iph && packet->iph->daddr == 0xffffffff &&
	    !memcmp(&packet->payload[17],"LanSearch",9)) {
		NDPI_LOG(NDPI_PROTOCOL_CSGO, ndpi_struct, NDPI_LOG_DEBUG,
			 "found csgo LanSearch udp.\n");
		ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
		return;
	}
  }
  if (flow->packet_counter > 20)
	  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_CSGO);
}


void init_csgo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("CSGO", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_CSGO,
				      ndpi_search_csgo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif

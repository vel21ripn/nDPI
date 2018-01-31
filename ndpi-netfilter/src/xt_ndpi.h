/*  Don't edit this file! Source file src/xt_ndpi.h.src */

/* 
 * xt_ndpi.h
 * Copyright (C) 2010-2012 G. Elian Gidoni <geg@gnu.org>
 *               2012 Ed Wildgoose <lists@wildgooses.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _LINUX_NETFILTER_XT_NDPI_H
#define _LINUX_NETFILTER_XT_NDPI_H 1

#include <linux/netfilter.h>
#include "ndpi_main.h"

#ifndef NDPI_BITMASK_IS_ZERO
#define NDPI_BITMASK_IS_ZERO(a) NDPI_BITMASK_IS_EMPTY(a)
#endif

struct xt_ndpi_mtinfo {
        NDPI_PROTOCOL_BITMASK flags;
	unsigned short int    invert:1,error:1,m_proto:1,p_proto:1,have_master:1;
};

struct xt_ndpi_tginfo {
       __u32 mark, mask;
       __u16 p_proto_id:1,m_proto_id:1,any_proto_id,t_accept:1,t_mark:1,t_clsf:1;
};

#ifndef NDPI_PROTOCOL_SHORT_STRING
#define NDPI_PROTOCOL_SHORT_STRING "unknown",	"ftp_control",     "mail_pop",             "mail_smtp",    "mail_imap",       "dns",\
"ipp",             "http",                 "mdns",         "ntp",             "netbios",\
"nfs",             "ssdp",                 "bgp",          "snmp",            "xdmcp",\
"smb",             "syslog",               "dhcp",         "postgres",        "mysql",\
"hotmail",         "direct_download_link", "mail_pops",    "applejuice",      "directconnect",\
"socrates",        "coap",                 "vmware",       "mail_smtps",      "filetopia",\
"ubntac2",         "kontiki",              "openft",       "fasttrack",       "gnutella",\
"edonkey",         "bittorrent",           "epp",          "avi",             "flash",\
"ogg",             "mpeg",                 "quicktime",    "realmedia",       "windowsmedia",\
"mms",             "xbox",                 "qq",           "move",            "rtsp",\
"mail_imaps",      "icecast",              "pplive",       "ppstream",        "zattoo",\
"shoutcast",       "sopcast",              "tvants",       "tvuplayer",       "http_download",\
"qqlive",          "thunder",              "soulseek",     "ssl_no_cert",     "irc",\
"ayiya",           "unencrypted_jabber",   "msn",          "oscar",           "yahoo",\
"battlefield",     "google_plus",          "ip_vrrp",      "steam",           "halflife2",\
"worldofwarcraft", "telnet",               "stun",         "ip_ipsec",        "ip_gre",\
"ip_icmp",         "ip_igmp",              "ip_egp",       "ip_sctp",         "ip_ospf",\
"ip_ip_in_ip",     "rtp",                  "rdp",          "vnc",             "pcanywhere",\
"ssl",             "ssh",                  "usenet",       "mgcp",            "iax",\
"tftp",            "afp",                  "stealthnet",   "aimini",          "sip",\
"truphone",        "ip_icmpv6",            "dhcpv6",       "armagetron",      "crossfire",\
"dofus",           "fiesta",               "florensia",    "guildwars",       "http_app_activesync",\
"kerberos",        "ldap",                 "maplestory",   "mssql_tds",       "pptp",\
"warcraft3",       "world_of_kung_fu",     "slack",        "facebook",        "twitter",\
"dropbox",         "gmail",                "google_maps",  "youtube",         "skype",\
"google",          "dcerpc",               "netflow",      "sflow",           "http_connect",\
"http_proxy",      "citrix",               "netflix",      "lastfm",          "waze",\
"youtube_upload",  "icq",                  "checkmk",      "citrix_online",   "apple",\
"webex",           "whatsapp",             "apple_icloud", "viber",           "apple_itunes",\
"radius",          "windows_update",       "teamviewer",   "tuenti",          "lotus_notes",\
"sap",             "gtp",                  "upnp",         "llmnr",           "remote_scan",\
"spotify",         "webm",                 "h323",         "openvpn",         "noe",\
"ciscovpn",        "teamspeak",            "tor",          "skinny",          "rtcp",\
"rsync",           "oracle",               "corba",        "ubuntuone",       "whois_das",\
"collectd",        "socks",                "nintendo",     "rtmp",            "ftp_data",\
"wikipedia",       "zmq",                  "amazon",       "ebay",            "cnn",\
"megaco",          "redis",                "pando",        "vhua",            "telegram",\
"vevo",            "pandora",              "quic",         "whatsapp_voice",  "eaq",\
"ookla",           "amqp",                 "kakaotalk",    "kakaotalk_voice", "twitch",\
"quickplay",       "wechat",               "mpegts",       "snapchat",        "sina",\
"hangout",         "iflix",                "github",       "bjnp",            "1kxun",\
"iqiyi",           "smpp",                 "dnscrypt",     "badproto_209",    "deezer",\
"instagram",       "microsoft",            "starcraft",    "teredo",          "hotspot_shield",\
"hep",             "google_drive",         "ocs",          "office_365",      "cloudflare",\
"ms_one_drive",    "mqtt",                 "rx",           "applestore",      "opendns",\
"git",             "drda",                 "playstore",    "someip",          "fix",\
"playstation",     "pastebin",             "linkedin",     "soundcloud",      "csgo",\
"lisp",            "diameter",             "apple_push",   "google_services"
#define NDPI_PROTOCOL_MAXNUM 239
#endif

#endif /* _LINUX_NETFILTER_XT_NDPI_H */

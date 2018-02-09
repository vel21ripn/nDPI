/*
 * ndpi_content_match.c
 *
 * Copyright (C) 2011-15 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

typedef struct {
  char *string_to_match, *proto_name;
  int protocol_id;
  ndpi_protocol_breed_t protocol_breed;
} ndpi_protocol_match;

typedef struct {
  u_int32_t network;
  u_int8_t cidr;
  u_int8_t value;
} ndpi_network;

/* ****************************************************** */


/* ****************************************************** */

/*
  Host-based match

  HTTP:  Server: field
  HTTPS: Server certificate name
*/

ndpi_protocol_match host_match[] = {
  { "amazon.",  			"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { "amazon.com",  			"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { "images-amazon.com", 		"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { "amazonaws.com",			"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { "amazon-adsystem.com",		"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { ".apple.com",			"Apple",		NDPI_SERVICE_APPLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".mzstatic.com",			"Apple",		NDPI_SERVICE_APPLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".icloud.com",			"AppleiCloud",		NDPI_SERVICE_APPLE_ICLOUD, NDPI_PROTOCOL_ACCEPTABLE },
  { "itunes.apple.com",			"AppleiTunes",		NDPI_SERVICE_APPLE_ITUNES, NDPI_PROTOCOL_FUN },
  { ".cnn.c",				"CNN",			NDPI_SERVICE_CNN, NDPI_PROTOCOL_FUN },
  { ".cnn.net",				"CNN",			NDPI_SERVICE_CNN, NDPI_PROTOCOL_FUN },
  { ".dropbox.com",			"DropBox",		NDPI_SERVICE_DROPBOX, NDPI_PROTOCOL_SAFE },
  { ".ebay.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".ebaystatic.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".ebaydesc.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".ebayrtm.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".facebook.com",			"Facebook",		NDPI_SERVICE_FACEBOOK, NDPI_PROTOCOL_FUN },
  { ".fbcdn.net",			"Facebook",		NDPI_SERVICE_FACEBOOK, NDPI_PROTOCOL_FUN },
  { "fbcdn-",				"Facebook",		NDPI_SERVICE_FACEBOOK, NDPI_PROTOCOL_FUN },  /* fbcdn-video-a-akamaihd.net */
  { ".google.",				"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".gstatic.com",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".googlesyndication.com",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".googletagservices.com",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".2mdn.net",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".doubleclick.net",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE }, /* Ads */
  { "googleads.",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "google-analytics.",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "googleusercontent.",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "googleadservices.",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "googleapis.com",	   	        "Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "ggpht.com",	   	        "Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "maps.google.",			"GoogleMaps",		NDPI_SERVICE_GOOGLE_MAPS, NDPI_PROTOCOL_ACCEPTABLE },
  { "maps.gstatic.com",			"GoogleMaps",		NDPI_SERVICE_GOOGLE_MAPS, NDPI_PROTOCOL_ACCEPTABLE },
  { ".gmail.",				"GMail",		NDPI_SERVICE_GMAIL, NDPI_PROTOCOL_SAFE },
  { "mail.google.",			"GMail",		NDPI_SERVICE_GMAIL, NDPI_PROTOCOL_SAFE },
  { ".last.fm",				"LastFM",		NDPI_SERVICE_LASTFM, NDPI_PROTOCOL_FUN },
  { "msn.com",				"MSN",			NDPI_SERVICE_MSN, NDPI_PROTOCOL_FUN },
  { "netflix.com",			"NetFlix",		NDPI_SERVICE_NETFLIX, NDPI_PROTOCOL_FUN	},
  { "nflxext.com",			"NetFlix",		NDPI_SERVICE_NETFLIX, NDPI_PROTOCOL_FUN	},
  { "nflximg.com",			"NetFlix",		NDPI_SERVICE_NETFLIX, NDPI_PROTOCOL_FUN },
  { "nflximg.net",			"NetFlix",		NDPI_SERVICE_NETFLIX, NDPI_PROTOCOL_FUN },

  { ".skype.",				"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypeassets.",			"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypedata.",			"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypeecs-", /* no final . */	"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".tuenti.com",			"Tuenti",		NDPI_SERVICE_TUENTI, NDPI_PROTOCOL_ACCEPTABLE },
  { ".twttr.com",			"Twitter",		NDPI_SERVICE_TWITTER, NDPI_PROTOCOL_ACCEPTABLE },
  { "twitter.",				"Twitter",		NDPI_SERVICE_TWITTER, NDPI_PROTOCOL_ACCEPTABLE },
  { "twimg.com",			"Twitter",		NDPI_SERVICE_TWITTER, NDPI_PROTOCOL_ACCEPTABLE },
  { ".viber.com",			"Viber",		NDPI_SERVICE_VIBER, NDPI_PROTOCOL_ACCEPTABLE },
  { "wikipedia.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "wikimedia.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "mediawiki.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "wikimediafoundation.",		"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { ".whatsapp.net",			"WhatsApp",		NDPI_SERVICE_WHATSAPP, NDPI_PROTOCOL_ACCEPTABLE },
  { ".yahoo.",				"Yahoo",		NDPI_SERVICE_YAHOO, NDPI_PROTOCOL_ACCEPTABLE },
  { "yimg.com",				"Yahoo",		NDPI_SERVICE_YAHOO, NDPI_PROTOCOL_ACCEPTABLE },
  { "yahooapis.",			"Yahoo",		NDPI_SERVICE_YAHOO, NDPI_PROTOCOL_ACCEPTABLE },
  { "youtube.",				"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { ".googlevideo.com",			"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { ".ytimg.com",			"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { "youtube-nocookie.",		"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { ".vevo.com",			"Vevo",			NDPI_SERVICE_VEVO,    NDPI_PROTOCOL_FUN },
  { ".spotify.",			"Spotify",		NDPI_PROTOCOL_SPOTIFY, NDPI_PROTOCOL_FUN },
  { ".pandora.com",			"Pandora",		NDPI_SERVICE_PANDORA,  NDPI_PROTOCOL_FUN },
  { ".torproject.org",                  "Tor",                  NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },
  { "appmeutim.tim.com.br",             "TIM_Meu",              NDPI_SERVICE_TIMMEU, NDPI_PROTOCOL_ACCEPTABLE },
  { ".timtorcedor.com.br",              "Torcedor",             NDPI_SERVICE_TORCEDOR, NDPI_PROTOCOL_ACCEPTABLE },
  { ".kakao.com",                       "KakaoTalk",            NDPI_SERVICE_KAKAOTALK, NDPI_PROTOCOL_FUN },
  { "ttvnw.net",                        "Twitch",               NDPI_SERVICE_TWITCH, NDPI_PROTOCOL_FUN },
  { "static-cdn.jtvnw.net",             "Twitch",               NDPI_SERVICE_TWITCH, NDPI_PROTOCOL_FUN },
  { "www-cdn.jtvnw.net",                "Twitch",               NDPI_SERVICE_TWITCH, NDPI_PROTOCOL_FUN },
  { "quickplay.com",                    "QuickPlay",            NDPI_SERVICE_QUICKPLAY, NDPI_PROTOCOL_FUN },
  { "tim.com.br",                       "TIM",                  NDPI_SERVICE_TIM, NDPI_PROTOCOL_ACCEPTABLE },
  { "tim.it",                           "TIM",                  NDPI_SERVICE_TIM, NDPI_PROTOCOL_ACCEPTABLE },

  /* https://support.cipafilter.com/index.php?/Knowledgebase/Article/View/117/0/snapchat---how-to-block */
  { "feelinsonice.appspot.com",         "Snapchat",             NDPI_SERVICE_SNAPCHAT, NDPI_PROTOCOL_FUN },
  { "feelinsonice-hrd.appspot.com",     "Snapchat",             NDPI_SERVICE_SNAPCHAT, NDPI_PROTOCOL_FUN },
  { "feelinsonice.com",                 "Snapchat",             NDPI_SERVICE_SNAPCHAT, NDPI_PROTOCOL_FUN },

  /* Detected "instagram.c10r.facebook.com". Omitted "*amazonaws.com" and "*facebook.com" CDNs e.g. "ig-telegraph-shv-04-frc3.facebook.com" */
  { ".cdninstagram.com",                "Instagram",            NDPI_SERVICE_INSTAGRAM, NDPI_PROTOCOL_FUN },
  { "instagram.",                       "Instagram",            NDPI_SERVICE_INSTAGRAM, NDPI_PROTOCOL_FUN },
  { ".instagram.",                      "Instagram",            NDPI_SERVICE_INSTAGRAM, NDPI_PROTOCOL_FUN },
  { "igcdn-photos-",                    "Instagram",            NDPI_SERVICE_INSTAGRAM, NDPI_PROTOCOL_FUN },
  { "instagramimages-",                 "Instagram",            NDPI_SERVICE_INSTAGRAM, NDPI_PROTOCOL_FUN },
  { "instagramstatic-",                 "Instagram",            NDPI_SERVICE_INSTAGRAM, NDPI_PROTOCOL_FUN },

  { ".waze.com",                        "Waze",                 NDPI_SERVICE_WAZE, NDPI_PROTOCOL_ACCEPTABLE },
  { "simet-",                           "Simet",                NDPI_SERVICE_SIMET, NDPI_PROTOCOL_ACCEPTABLE },
  { "opensignal.com",                   "OpenSignal",           NDPI_SERVICE_OPENSIGNAL, NDPI_PROTOCOL_ACCEPTABLE },
  { "99taxis.com",                      "99Taxi",               NDPI_SERVICE_99TAXI, NDPI_PROTOCOL_ACCEPTABLE },
  { "easytaxis.com",                    "EasyTaxi",             NDPI_SERVICE_EASYTAXI, NDPI_PROTOCOL_ACCEPTABLE },
  { ".globo.com",                       "GloboTV",              NDPI_SERVICE_GLOBOTV, NDPI_PROTOCOL_ACCEPTABLE },
  { ".glbimg.com",                      "GloboTV",              NDPI_SERVICE_GLOBOTV, NDPI_PROTOCOL_ACCEPTABLE },
  { "timsomdechamada.com.br",           "SomDeChamada",         NDPI_SERVICE_TIMSOMDECHAMADA, NDPI_PROTOCOL_ACCEPTABLE },
  { ".tim.acotelbr.com.br",             "TIM_Menu",             NDPI_SERVICE_TIMMENU, NDPI_PROTOCOL_ACCEPTABLE },
  { ".timbeta.com.br",                  "TIM_Beta",             NDPI_SERVICE_TIMBETA, NDPI_PROTOCOL_ACCEPTABLE },
  { "tim-geoportal.geoportal3d.com.br", "TIM_PortasAbertas",    NDPI_SERVICE_TIMPORTASABERTAS, NDPI_PROTOCOL_ACCEPTABLE },
  { ".m4u.com.br",                      "TIM_Recarga",          NDPI_SERVICE_TIMRECARGA, NDPI_PROTOCOL_ACCEPTABLE },
  { ".deezer.com",                      "Deezer",               NDPI_SERVICE_DEEZER, NDPI_PROTOCOL_ACCEPTABLE },
  { ".microsoft.com",                   "Microsoft",            NDPI_SERVICE_MICROSOFT, NDPI_PROTOCOL_ACCEPTABLE },
  { "update.microsoft.com",             "WindowsUpdate",        NDPI_SERVICE_WINDOWS_UPDATE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".windowsupdate.com",               "WindowsUpdate",        NDPI_SERVICE_WINDOWS_UPDATE, NDPI_PROTOCOL_ACCEPTABLE },
  { "worldofwarcraft.com",              "WorldOfWarcraft",      NDPI_PROTOCOL_WORLDOFWARCRAFT, NDPI_PROTOCOL_FUN },
  { ".anchorfree.",                     "HotspotShield",        NDPI_SERVICE_HOTSPOT_SHIELD, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },
  { "hotspotshield.com",                "HotspotShield",        NDPI_SERVICE_HOTSPOT_SHIELD, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS },
  { NULL, 0 }
};


/*
  Mime-type content match match
*/
ndpi_protocol_match content_match[] = {
  { "audio/mpeg",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/x-mpeg",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/mpeg3",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/mp4a",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "video/mpeg",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "video/nsv",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "misc/ultravox",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/ogg",			NULL,		        NDPI_CONTENT_OGG, NDPI_PROTOCOL_FUN },
  { "video/ogg",			NULL,		        NDPI_CONTENT_OGG, NDPI_PROTOCOL_FUN },
  { "application/ogg",			NULL,		        NDPI_CONTENT_OGG, NDPI_PROTOCOL_FUN },
  { "video/flv",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "video/x-flv",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/x-fcs",		NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/x-shockwave-flash",	NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_ACCEPTABLE },
  { "video/flash",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/flv",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "flv-application/octet-stream",	NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/futuresplash",		NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "video/quicktime",			NULL,		        NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_FUN },
  { "video/mp4",			NULL,		        NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_FUN },
  { "video/x-m4v",			NULL,		        NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_FUN },
  { "audio/x-pn-realaudio",		NULL,		        NDPI_CONTENT_REALMEDIA, NDPI_PROTOCOL_FUN },
  { "application/vnd.rn-realmedia",	NULL,		        NDPI_CONTENT_REALMEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-ms-",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "asf",			        NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "asx",			        NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-msvideo",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "audio/x-wav",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "application/vnd.ms.wms-hdr.asfv1",	NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "NSPlayer/",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "application/x-mms-framed",		NULL,		        NDPI_CONTENT_MMS, NDPI_PROTOCOL_FUN },
  { "Xbox Live Client/",		NULL,		        NDPI_PROTOCOL_XBOX, NDPI_PROTOCOL_FUN },
  { "Windows-Update-Agent",		NULL,		        NDPI_SERVICE_WINDOWS_UPDATE, NDPI_PROTOCOL_ACCEPTABLE },
  { "audio/webm",			NULL,		        NDPI_CONTENT_WEBM, NDPI_PROTOCOL_FUN },
  { "video/webm",			NULL,		        NDPI_CONTENT_WEBM, NDPI_PROTOCOL_FUN },
  { "application/x-rtsp-tunnelled",	NULL,		        NDPI_PROTOCOL_RTSP, NDPI_PROTOCOL_FUN },
  { "application/vnd.apple.mpegurl",	NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { NULL, 0 }
};

/* ****************************************************** */

/*
  Tor
  The tor protocol uses SSL to contact peers so it could be exchanged with
  standard SSL. However the host names such as

  - www.fgd2iwya7vinfutj5wq5we.com
  - www.qbtxzhetq4s2f.com
  - www.fgd2iwya7vinfutj5wq5we.net

  In essence www.<name>.com|net

  To do things properly we should check if host name in the certificate
  exists or if the IP address of the SSL peer resolves to a name. Unfortunately
  for performance reasons we can't afford to do a DNS lookup in nDPI (however apps
  can do it if possible) and thus we have created a heuristic algorithm that tries
  to check the host name (in the SSL certificate) to see if it looks like a
  random name or a real name. We cannot use a dictionary (how can the kernel read a file?)
  and this we use bigrams distribution to decide if the string looks like a
  word or just random chars.

  http://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html
*/

static const char *ndpi_en_bigrams[] = {
  "aa", "ba", "ca", "da", "ea", "fa", "ga", "ha", "ia", "ja", "ka", "la", "ma", "na", "oa", "pa", "qa",
  "ra", "sa", "ta", "ua", "va", "wa", "xa", "ya", "za", "ab", "bb", "db", "eb", "fb", "gb", "hb", "ib",
  "kb", "lb", "mb", "nb", "ob", "pb", "rb", "sb", "tb", "ub", "wb", "yb", "ac", "bc", "cc", "dc", "ec",
  "fc", "gc", "hc", "ic", "kc", "lc", "mc", "nc", "oc", "pc", "rc", "sc", "tc", "uc", "wc", "xc", "yc",
  "ad", "bd", "cd", "dd", "ed", "fd", "gd", "hd", "id", "kd", "ld", "md", "nd", "od", "pd", "rd", "sd",
  "td", "ud", "wd", "xd", "yd", "zd", "ae", "be", "ce", "de", "ee", "fe", "ge", "he", "ie", "je", "ke",
  "le", "me", "ne", "oe", "pe", "re", "se", "te", "ue", "ve", "we", "xe", "ye", "ze", "af", "bf", "df",
  "ef", "ff", "gf", "hf", "if", "kf", "lf", "mf", "nf", "of", "pf", "rf", "sf", "tf", "uf", "wf", "xf",
  "yf", "zf", "ag", "bg", "dg", "eg", "fg", "gg", "hg", "ig", "kg", "lg", "ng", "og", "pg", "rg", "sg",
  "tg", "ug", "wg", "yg", "ah", "bh", "ch", "dh", "eh", "fh", "gh", "hh", "ih", "kh", "lh", "mh", "nh",
  "oh", "ph", "rh", "sh", "th", "uh", "wh", "xh", "yh", "ai", "bi", "ci", "di", "ei", "fi", "gi", "hi",
  "ii", "ji", "ki", "li", "mi", "ni", "oi", "pi", "qi", "ri", "si", "ti", "ui", "vi", "wi", "xi", "yi",
  "zi", "aj", "bj", "dj", "ej", "fj", "gj", "hj", "ij", "jj", "kj", "lj", "nj", "oj", "pj", "rj", "sj",
  "tj", "uj", "wj", "yj", "ak", "ck", "dk", "ek", "gk", "ik", "kk", "lk", "mk", "nk", "ok", "pk", "rk",
  "sk", "tk", "uk", "wk", "yk", "zk", "al", "bl", "cl", "dl", "el", "fl", "gl", "hl", "il", "kl", "ll",
  "ml", "nl", "ol", "pl", "rl", "sl", "tl", "ul", "vl", "wl", "xl", "yl", "zl", "am", "bm", "cm", "dm",
  "em", "fm", "gm", "hm", "im", "km", "lm", "mm", "nm", "om", "pm", "rm", "sm", "tm", "um", "wm", "xm",
  "ym", "zm", "an", "bn", "cn", "dn", "en", "fn", "gn", "hn", "in", "kn", "ln", "mn", "nn", "on", "pn",
  "rn", "sn", "tn", "un", "wn", "xn", "yn", "ao", "bo", "co", "do", "eo", "fo", "go", "ho", "io", "jo",
  "ko", "lo", "mo", "no", "oo", "po", "ro", "so", "to", "uo", "vo", "wo", "xo", "yo", "zo", "ap", "bp",
  "dp", "ep", "fp", "gp", "hp", "ip", "kp", "lp", "mp", "np", "op", "pp", "rp", "sp", "tp", "up", "wp",
  "xp", "yp", "zp", "aq", "cq", "dq", "eq", "hq", "iq", "nq", "oq", "qq", "rq", "sq", "uq", "xq", "ar",
  "br", "cr", "dr", "er", "fr", "gr", "hr", "ir", "kr", "lr", "mr", "nr", "or", "pr", "rr", "sr", "tr",
  "ur", "vr", "wr", "xr", "yr", "as", "bs", "cs", "ds", "es", "fs", "gs", "hs", "is", "ks", "ls", "ms",
  "ns", "os", "ps", "rs", "ss", "ts", "us", "vs", "ws", "xs", "ys", "at", "bt", "ct", "dt", "et", "ft",
  "gt", "ht", "it", "kt", "lt", "mt", "nt", "ot", "pt", "rt", "st", "tt", "ut", "wt", "xt", "yt", "zt",
  "au", "bu", "cu", "du", "eu", "fu", "gu", "hu", "iu", "ju", "ku", "lu", "mu", "nu", "ou", "pu", "qu",
  "ru", "su", "tu", "uu", "vu", "wu", "xu", "yu", "zu", "av", "bv", "dv", "ev", "iv", "lv", "mv", "nv",
  "ov", "rv", "sv", "tv", "uv", "vv", "zv", "aw", "bw", "dw", "ew", "fw", "gw", "hw", "iw", "kw", "lw",
  "mw", "nw", "ow", "pw", "rw", "sw", "tw", "uw", "ww", "xw", "yw", "zw", "ax", "ex", "ix", "nx", "ox",
  "rx", "ux", "xx", "yx", "ay", "by", "cy", "dy", "ey", "fy", "gy", "hy", "ky", "ly", "my", "ny", "oy",
  "py", "ry", "sy", "ty", "uy", "vy", "wy", "xy", "yy", "zy", "az", "bz", "cz", "dz", "ez", "gz", "iz",
  "lz", "nz", "oz", "pz", "rz", "tz", "uz", "zz", NULL };

static const char *ndpi_en_impossible_bigrams[] = {
  "bk", "bq", "bx", "cb", "cf", "cg", "cj", "cp", "cv", "cw", "cx", "dx", "fk", "fq", "fv", "fx", "ee",
  "fz", "gq", "gv", "gx", "hh", "hk", "hv", "hx", "hz", "iy", "jb", "jc", "jd", "jf", "jg", "jh", "jk",
  "jl", "jm", "jn", "jp", "jq", "jr", "js", "jt", "jv", "jw", "jx", "jy", "jz", "kg", "kq", "kv", "kx",
  "kz", "lq", "lx", "mg", "mj", "mq", "mx", "mz", "pq", "pv", "px", "qb", "qc", "qd", "qe", "qf", "ii",
  "qg", "qh", "qj", "qk", "ql", "qm", "qn", "qo", "qp", "qr", "qs", "qt", "qv", "qw", "qx", "qy", "uu",
  "qz", "sx", "sz", "tq", "tx", "vb", "vc", "vd", "vf", "vg", "vh", "vj", "vk", "vm", "vn", "vp", "bw",
  "vq", "vt", "vw", "vx", "vz", "wq", "wv", "wx", "wz", "xb", "xg", "xj", "xk", "xv", "xz", "xw", "yd", "yp",
  "yj", "yq", "yv", "yz", "yw", "zb", "zc", "zg", "zh", "zj", "zn", "zq", "zr", "zs", "zx", "wh", "wk",
  "wb", "zk", "kp", "zk", "xy",
  NULL };

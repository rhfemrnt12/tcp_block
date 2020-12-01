/*
 *  $Id: libnet-headers.h,v 1.14 2004/03/11 18:50:20 mike Exp $
 *
 *  libnet-headers.h - Network routine library headers header file
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __LIBNET_HEADERS_H
#define __LIBNET_HEADERS_H
/**
 * @file libnet-headers.h
 * @brief libnet header information
 */

/**
 * Libnet defines header sizes for every builder function exported.
 */
#define LIBNET_802_1Q_H         0x12    /**< 802.1Q header:       18 bytes */
#define LIBNET_802_1X_H         0x04    /**< 802.1X header:        4 bytes */
#define LIBNET_802_2_H          0x03    /**< 802.2 LLC header:     3 bytes */
#define LIBNET_802_2SNAP_H      0x08    /**< 802.2 LLC/SNAP header:8 bytes */
#define LIBNET_802_3_H          0x0e    /**< 802.3 header:        14 bytes */
#define LIBNET_ARP_H            0x08    /**< ARP header w/o addrs: 8 bytes */
#define LIBNET_ARP_ETH_IP_H     0x1c    /**< ARP w/ ETH and IP:   28 bytes */
#define LIBNET_BGP4_HEADER_H    0x13    /**< BGP header:          19 bytes */
#define LIBNET_BGP4_OPEN_H      0x0a    /**< BGP open header:     10 bytes */
#define LIBNET_BGP4_UPDATE_H    0x04    /**< BGP open header:      4 bytes */
#define LIBNET_BGP4_NOTIFICATION_H 0x02 /**< BGP notif. header:    2 bytes */
#define LIBNET_CDP_H            0x08    /**< CDP header base:      8 bytes */
#define LIBNET_DHCPV4_H         0xf0    /**< DHCP v4 header:     240 bytes */
#define LIBNET_UDP_DNSV4_H      0x0c    /**< UDP DNS v4 header:   12 bytes */
#define LIBNET_TCP_DNSV4_H      0x0e    /**< TCP DNS v4 header:   14 bytes */
#define LIBNET_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define LIBNET_FDDI_H           0x15    /**< FDDI header:         21 bytes */
#define LIBNET_ICMPV4_H         0x04    /**< ICMP header base:     4 bytes */
#define LIBNET_ICMPV4_ECHO_H    0x08    /**< ICMP_ECHO header:     8 bytes */
#define LIBNET_ICMPV4_MASK_H    0x0c    /**< ICMP_MASK header:    12 bytes */
#define LIBNET_ICMPV4_UNREACH_H  0x08   /**< ICMP_UNREACH header:  8 bytes */
#define LIBNET_ICMPV4_TIMXCEED_H 0x08   /**< ICMP_TIMXCEED header: 8 bytes */
#define LIBNET_ICMPV4_REDIRECT_H 0x08   /**< ICMP_REDIRECT header: 8 bytes */
#define LIBNET_ICMPV4_TS_H      0x14    /**< ICMP_TIMESTAMP headr:20 bytes */
#define LIBNET_ICMPV6_H         0x08    /**< ICMP6 header base:    8 bytes */
#define LIBNET_IGMP_H           0x08    /**< IGMP header:          8 bytes */
#define LIBNET_IPV4_H           0x14    /**< IPv4 header:         20 bytes */
#define LIBNET_IPV6_H           0x28    /**< IPv6 header:         40 bytes */
#define LIBNET_IPV6_FRAG_H      0x08    /**< IPv6 frag header:     8 bytes */
#define LIBNET_IPV6_ROUTING_H   0x04    /**< IPv6 frag header base:4 bytes */
#define LIBNET_IPV6_DESTOPTS_H  0x02    /**< IPv6 dest opts base:  2 bytes */
#define LIBNET_IPV6_HBHOPTS_H   0x02    /**< IPv6 hop/hop opt base:2 bytes */
#define LIBNET_IPSEC_ESP_HDR_H  0x0c    /**< IPSEC ESP header:    12 bytes */
#define LIBNET_IPSEC_ESP_FTR_H  0x02    /**< IPSEC ESP footer:     2 bytes */
#define LIBNET_IPSEC_AH_H       0x10    /**< IPSEC AH header:     16 bytes */
#define LIBNET_ISL_H            0x1a    /**< ISL header:          26 bytes */
#define LIBNET_GRE_H            0x04    /**< GRE header:           4 bytes */
#define LIBNET_GRE_SRE_H        0x04    /**< GRE SRE header:       4 bytes */
#define LIBNET_MPLS_H           0x04    /**< MPLS header:          4 bytes */
#define LIBNET_OSPF_H           0x10    /**< OSPF header:         16 bytes */
#define LIBNET_OSPF_HELLO_H     0x18    /**< OSPF hello header:   24 bytes */
#define LIBNET_OSPF_DBD_H       0x08    /**< OSPF DBD header:      8 bytes */
#define LIBNET_OSPF_LSR_H       0x0c    /**< OSPF LSR header:     12 bytes */
#define LIBNET_OSPF_LSU_H       0x04    /**< OSPF LSU header:      4 bytes */
#define LIBNET_OSPF_LSA_H       0x14    /**< OSPF LSA header:     20 bytes */
#define LIBNET_OSPF_AUTH_H      0x08    /**< OSPF AUTH header:     8 bytes */
#define LIBNET_OSPF_CKSUM       0x10    /**< OSPF CKSUM header:   16 bytes */
#define LIBNET_OSPF_LS_RTR_H    0x10    /**< OSPF LS RTR header:  16 bytes */
#define LIBNET_OSPF_LS_NET_H    0x08    /**< OSPF LS NET header:   8 bytes */
#define LIBNET_OSPF_LS_SUM_H    0x0c    /**< OSPF LS SUM header:  12 bytes */
#define LIBNET_OSPF_LS_AS_EXT_H 0x10    /**< OSPF LS AS header:   16 bytes */
#define LIBNET_NTP_H            0x30    /**< NTP header:          48 bytes */
#define LIBNET_RIP_H            0x18    /**< RIP header base:     24 bytes */
#define LIBNET_RPC_CALL_H       0x28    /**< RPC header:          40 bytes
                                         * (assuming 8 byte auth header)
                                         */
#define LIBNET_RPC_CALL_TCP_H   0x2c    /**< RPC header:          44 bytes
                                         * (with record marking)
                                         */
#define LIBNET_SEBEK_H          0x30    /* sebek header:          48 bytes */   
#define LIBNET_STP_CONF_H       0x23    /**< STP conf header:     35 bytes */
#define LIBNET_STP_TCN_H        0x04    /**< STP tcn header:       4 bytes */
#define LIBNET_TOKEN_RING_H     0x16    /**< Token Ring header:   22 bytes */
#define LIBNET_TCP_H            0x14    /**< TCP header:          20 bytes */
#define LIBNET_UDP_H            0x08    /**< UDP header:           8 bytes */
#define LIBNET_VRRP_H           0x08    /**< VRRP header:          8 bytes */
#define 	ETHER_ADDR_LEN   6
/**
 * IEEE 802.1Q (Virtual Local Area Network) VLAN header, static header 
 * size: 18 bytes
 */
struct libnet_802_1q_hdr
{
    u_int8_t vlan_dhost[ETHER_ADDR_LEN];  /**< destination ethernet address */
    u_int8_t vlan_shost[ETHER_ADDR_LEN];  /**< source ethernet address */
    u_int16_t vlan_tpi;                   /**< tag protocol ID */
    u_int16_t vlan_priority_c_vid;        /**< priority | VLAN ID */
#define LIBNET_802_1Q_PRIMASK   0x0007    /**< priority mask */
#define LIBNET_802_1Q_CFIMASK   0x0001    /**< CFI mask */
#define LIBNET_802_1Q_VIDMASK   0x0fff    /**< vid mask */
    u_int16_t vlan_len;                   /**< length or type (802.3 / Eth 2) */
};  

/**
 * IEEE 802.1X EAP (Extensible Authentication Protocol) header, static header
 * size: 4 bytes
 */
struct libnet_802_1x_hdr
{
    u_int8_t dot1x_version;               /**< protocol version */
    u_int8_t dot1x_type;                  /**< frame type */
#define LIBNET_802_1X_PACKET    0x00      /**< 802.1x packet */
#define LIBNET_802_1X_START     0x01      /**< 802.1x start */
#define LIBNET_802_1X_LOGOFF    0x02      /**< 802.1x logoff */
#define LIBNET_802_1X_KEY       0x03      /**< 802.1x key */
#define LIBNET_802_1X_ENCASFAL  0x04      /**< 802.1x encasfal */
    u_int16_t dot1x_length;               /**< total frame length */
};  

/*
 *  IEEE 802.2 LLC header
 *  Link Layer Control
 *  static header size: 3 bytes
 */
struct libnet_802_2_hdr
{
    u_int8_t llc_dsap;            /* destination service access point */
    u_int8_t llc_ssap;            /* source service access point */
#define LIBNET_SAP_STP          0x42
#define LIBNET_SAP_SNAP         0xaa
    u_int8_t llc_control;         /* control field */
};


/*
 *  IEEE 802.2 LLC/SNAP header
 *  SubNetwork Attachment Point
 *  static header size: 8 bytes
 */
struct libnet_802_2snap_hdr
{
    u_int8_t snap_dsap;           /* destination service access point */
    u_int8_t snap_ssap;           /* destination service access point */
    u_int8_t snap_control;        /* control field */
    u_int8_t snap_oui[3];         /* OUI */
    u_int16_t snap_type;          /* type */
};


/*
 *  802.3 header
 *  IEEE Ethernet
 *  Static header size: 14 bytes
 */
struct libnet_802_3_hdr
{
    u_int8_t  _802_3_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  _802_3_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t _802_3_len;                 /* packet type ID */
};


/* 
 *  ARP header
 *  Address Resolution Protocol
 *  Base header size: 8 bytes
 */
struct libnet_arp_hdr
{
    u_int16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    u_int16_t ar_pro;         /* format of protocol address */
    u_int8_t  ar_hln;         /* length of hardware address */
    u_int8_t  ar_pln;         /* length of protocol addres */
    u_int16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
};

/*
 * BGP4 header
 * Border Gateway Protocol 4
 * Base header size : 19 bytes
 */
struct libnet_bgp4_header_hdr
{
#define LIBNET_BGP4_MARKER_SIZE   16
    u_int8_t marker[LIBNET_BGP4_MARKER_SIZE];
    u_int16_t len;
    u_int8_t type;
#define LIBNET_BGP4_OPEN          1
#define LIBNET_BGP4_UPDATE        2
#define LIBNET_BGP4_NOTIFICATION  3
#define LIBNET_BGP4_KEEPALIVE     4
};

/*
 * BGP4 open header
 * Border Gateway Protocol 4
 * Base header size : 10 bytes
 */
struct libnet_bgp4_open_hdr
{
    u_int8_t version;
    u_int16_t src_as;
    u_int16_t hold_time;
    u_int32_t bgp_id;
    u_int8_t opt_len;
};

/*
 * BGP4 notification message
 *
 * Border Gateway Protocol 4
 * Base header size : 2 bytes
 *
 * Use payload if you need data
 */
struct libnet_bgp4_notification_hdr
{
#define LIBNET_BGP4_MESSAGE_HEADER_ERROR  1
#define LIBNET_BGP4_OPEN_MESSAGE_ERROR    2
#define LIBNET_BGP4_UPDATE_MESSAGE_ERROR  3
#define LIBNET_BGP4_HOLD_TIMER_EXPIRED    4
#define LIBNET_BGP4_FINITE_STATE__ERROR   5
#define LIBNET_BGP4_CEASE                 6
    u_int8_t err_code;

/* Message Header Error subcodes */
#define LIBNET_BGP4_CONNECTION_NOT_SYNCHRONIZED    1
#define LIBNET_BGP4_BAD_MESSAGE_LENGTH             2
#define LIBNET_BGP4_BAD_MESSAGE_TYPE               3
/* OPEN Message Error subcodes */
#define LIBNET_BGP4_UNSUPPORTED_VERSION_NUMBER     1
#define LIBNET_BGP4_BAD_PEER_AS                    2
#define LIBNET_BGP4_BAD_BGP_IDENTIFIER             3
#define LIBNET_BGP4_UNSUPPORTED_OPTIONAL_PARAMETER 4
#define LIBNET_BGP4_AUTHENTICATION_FAILURE         5
#define LIBNET_BGP4_UNACCEPTABLE_HOLD_TIME         6
/* UPDATE Message Error subcodes */
#define LIBNET_BGP4_MALFORMED_ATTRIBUTE_LIST
#define LIBNET_BGP4_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE
#define LIBNET_BGP4_MISSING_WELL_KNOWN_ATTRIBUTE
#define LIBNET_BGP4_ATTRIBUTE_FLAGS_ERROR
#define LIBNET_BGP4_ATTRIBUTE_LENGTH_ERROR
#define LIBNET_BGP4_INVALID_ORIGIN_ATTRIBUTE
#define LIBNET_BGP4_AS_ROUTING_LOOP
#define LIBNET_BGP4_INVALID_NEXT_HOP_ATTRIBUTE
#define LIBNET_BGP4_OPTIONAL_ATTRIBUTE_ERROR
#define LIBNET_BGP4_INVALID_NETWORK_FIELD
#define LIBNET_BGP4_MALFORMED_AS_PATH
    u_int8_t err_subcode;
};



/*
 *  CDP header
 *  Cisco Discovery Protocol
 *  Base header size: 8 bytes
 */

/*
 *  For checksum stuff -- IANA says 135-254 is "unassigned" as of 12.2001.
 *  Let's hope this one stays that way for a while!
 */
#define LIBNET_PROTO_CDP    200
struct libnet_cdp_hdr
{
    u_int8_t cdp_version;     /* version (should always be 0x01) */
    u_int8_t cdp_ttl;         /* time reciever should hold info in this packet */
    u_int16_t cdp_sum;        /* checksum */
    u_int16_t cdp_type;       /* type */
#define LIBNET_CDP_DEVID    0x1 /* device id */
#define LIBNET_CDP_ADDRESS  0x2 /* address */
#define LIBNET_CDP_PORTID   0x3 /* port id */
#define LIBNET_CDP_CAPABIL  0x4 /* capabilities */
#define LIBNET_CDP_VERSION  0x5 /* version */
#define LIBNET_CDP_PLATFORM 0x6 /* platform */
#define LIBNET_CDP_IPPREFIX 0x7 /* ip prefix */
    u_int16_t cdp_len;        /* type + length + value */
    /* value information done dynamically */

/* CDP capabilities */
#define LIBNET_CDP_CAP_L3R  0x01/* performs level 3 routing */
#define LIBNET_CDP_CAP_L2B  0x02/* performs level 2 transparent bridging */
#define LIBNET_CDP_CAP_L2SRB 0x04/* performs level 2 sourceroute bridging */
#define LIBNET_CDP_CAP_L2S  0x08/* performs level 2 switching */
#define LIBNET_CDP_CAP_SR   0x10/* sends and recieves packets on a network */
#define LIBNET_CDP_CAP_NOI  0x20/* does not forward IGMP on non-router ports */
#define LIBNET_CDP_CAP_L1F  0x40/* provides level 1 functionality */
};


/*
 *  Used as an overlay for type/len/values
 */
struct libnet_cdp_value_hdr
{
    u_int16_t cdp_type;
    u_int16_t cdp_len;
};


/*
 *  DHCP header
 *  Dynamic Host Configuration Protocol
 *  Static header size: f0 bytes
 */
struct libnet_dhcpv4_hdr
{
    u_int8_t dhcp_opcode;     /* opcode */
#define LIBNET_DHCP_REQUEST 0x1
#define LIBNET_DHCP_REPLY   0x2
    u_int8_t dhcp_htype;      /* hardware address type */
    u_int8_t dhcp_hlen;       /* hardware address length */
    u_int8_t dhcp_hopcount;   /* used by proxy servers */
    u_int32_t dhcp_xid;        /* transaction ID */
    u_int16_t dhcp_secs;      /* number of seconds since trying to bootstrap */
    u_int16_t dhcp_flags;     /* flags for DHCP, unused for BOOTP */
    u_int32_t dhcp_cip;        /* client's IP */
    u_int32_t dhcp_yip;        /* your IP */
    u_int32_t dhcp_sip;        /* server's IP */
    u_int32_t dhcp_gip;        /* gateway IP */
    u_int8_t dhcp_chaddr[16]; /* client hardware address */
    u_int8_t dhcp_sname[64];  /* server host name */
    u_int8_t dhcp_file[128];  /* boot file name */
    u_int32_t dhcp_magic;      /* BOOTP magic header */
#define DHCP_MAGIC                  0x63825363
#define LIBNET_BOOTP_MIN_LEN        0x12c
#define LIBNET_DHCP_PAD             0x00
#define LIBNET_DHCP_SUBNETMASK      0x01
#define LIBNET_DHCP_TIMEOFFSET      0x02
#define LIBNET_DHCP_ROUTER          0x03
#define LIBNET_DHCP_TIMESERVER      0x04
#define LIBNET_DHCP_NAMESERVER      0x05
#define LIBNET_DHCP_DNS             0x06
#define LIBNET_DHCP_LOGSERV         0x07
#define LIBNET_DHCP_COOKIESERV      0x08
#define LIBNET_DHCP_LPRSERV         0x09
#define LIBNET_DHCP_IMPSERV         0x0a
#define LIBNET_DHCP_RESSERV         0x0b
#define LIBNET_DHCP_HOSTNAME        0x0c
#define LIBNET_DHCP_BOOTFILESIZE    0x0d
#define LIBNET_DHCP_DUMPFILE        0x0e
#define LIBNET_DHCP_DOMAINNAME      0x0f
#define LIBNET_DHCP_SWAPSERV        0x10
#define LIBNET_DHCP_ROOTPATH        0x11
#define LIBNET_DHCP_EXTENPATH       0x12
#define LIBNET_DHCP_IPFORWARD       0x13
#define LIBNET_DHCP_SRCROUTE        0x14
#define LIBNET_DHCP_POLICYFILTER    0x15
#define LIBNET_DHCP_MAXASMSIZE      0x16
#define LIBNET_DHCP_IPTTL           0x17
#define LIBNET_DHCP_MTUTIMEOUT      0x18
#define LIBNET_DHCP_MTUTABLE        0x19
#define LIBNET_DHCP_MTUSIZE         0x1a
#define LIBNET_DHCP_LOCALSUBNETS    0x1b
#define LIBNET_DHCP_BROADCASTADDR   0x1c
#define LIBNET_DHCP_DOMASKDISCOV    0x1d
#define LIBNET_DHCP_MASKSUPPLY      0x1e
#define LIBNET_DHCP_DOROUTEDISC     0x1f
#define LIBNET_DHCP_ROUTERSOLICIT   0x20
#define LIBNET_DHCP_STATICROUTE     0x21
#define LIBNET_DHCP_TRAILERENCAP    0x22
#define LIBNET_DHCP_ARPTIMEOUT      0x23
#define LIBNET_DHCP_ETHERENCAP      0x24
#define LIBNET_DHCP_TCPTTL          0x25
#define LIBNET_DHCP_TCPKEEPALIVE    0x26
#define LIBNET_DHCP_TCPALIVEGARBAGE 0x27
#define LIBNET_DHCP_NISDOMAIN       0x28
#define LIBNET_DHCP_NISSERVERS      0x29
#define LIBNET_DHCP_NISTIMESERV     0x2a
#define LIBNET_DHCP_VENDSPECIFIC    0x2b
#define LIBNET_DHCP_NBNS            0x2c
#define LIBNET_DHCP_NBDD            0x2d
#define LIBNET_DHCP_NBTCPIP         0x2e
#define LIBNET_DHCP_NBTCPSCOPE      0x2f
#define LIBNET_DHCP_XFONT           0x30
#define LIBNET_DHCP_XDISPLAYMGR     0x31
#define LIBNET_DHCP_DISCOVERADDR    0x32
#define LIBNET_DHCP_LEASETIME       0x33
#define LIBNET_DHCP_OPTIONOVERLOAD  0x34
#define LIBNET_DHCP_MESSAGETYPE     0x35
#define LIBNET_DHCP_SERVIDENT       0x36
#define LIBNET_DHCP_PARAMREQUEST    0x37
#define LIBNET_DHCP_MESSAGE         0x38
#define LIBNET_DHCP_MAXMSGSIZE      0x39
#define LIBNET_DHCP_RENEWTIME       0x3a
#define LIBNET_DHCP_REBINDTIME      0x3b
#define LIBNET_DHCP_CLASSSID        0x3c
#define LIBNET_DHCP_CLIENTID        0x3d
#define LIBNET_DHCP_NISPLUSDOMAIN   0x40
#define LIBNET_DHCP_NISPLUSSERVERS  0x41
#define LIBNET_DHCP_MOBILEIPAGENT   0x44
#define LIBNET_DHCP_SMTPSERVER      0x45
#define LIBNET_DHCP_POP3SERVER      0x46
#define LIBNET_DHCP_NNTPSERVER      0x47
#define LIBNET_DHCP_WWWSERVER       0x48
#define LIBNET_DHCP_FINGERSERVER    0x49
#define LIBNET_DHCP_IRCSERVER       0x4a
#define LIBNET_DHCP_STSERVER        0x4b
#define LIBNET_DHCP_STDASERVER      0x4c
#define LIBNET_DHCP_END             0xff

#define LIBNET_DHCP_MSGDISCOVER     0x01
#define LIBNET_DHCP_MSGOFFER        0x02
#define LIBNET_DHCP_MSGREQUEST      0x03
#define LIBNET_DHCP_MSGDECLINE      0x04
#define LIBNET_DHCP_MSGACK          0x05
#define LIBNET_DHCP_MSGNACK         0x06
#define LIBNET_DHCP_MSGRELEASE      0x07
#define LIBNET_DHCP_MSGINFORM       0x08
};

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

#ifndef ETHERTYPE_PUP
#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_EAP
#define ETHERTYPE_EAP           0x888e  /* IEEE 802.1X EAP authentication */
#endif
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS          0x8847  /* MPLS */
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */
#endif

struct libnet_ether_addr
{
    u_int8_t  ether_addr_octet[6];        /* Ethernet address */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */

    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  IP options
 */
#ifndef IPOPT_EOL
#define IPOPT_EOL       0   /* end of option list */
#endif
#ifndef IPOPT_NOP
#define IPOPT_NOP       1   /* no operation */
#endif   
#ifndef IPOPT_RR
#define IPOPT_RR        7   /* record packet route */
#endif
#ifndef IPOPT_TS
#define IPOPT_TS        68  /* timestamp */
#endif
#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   
#endif
#ifndef IPOPT_LSRR
#define IPOPT_LSRR      131 /* loose source route */
#endif
#ifndef IPOPT_SATID
#define IPOPT_SATID     136 /* satnet id */
#endif
#ifndef IPOPT_SSRR
#define IPOPT_SSRR      137 /* strict source route */
#endif

struct libnet_in6_addr
{
    union
    {
        u_int8_t   __u6_addr8[16];
        u_int16_t  __u6_addr16[8];
        u_int32_t  __u6_addr32[4];
    } __u6_addr;            /* 128-bit IP6 address */
};
#define libnet_s6_addr __u6_addr.__u6_addr8

/*
 *  IPv6 header
 *  Internet Protocol, version 6
 *  Static header size: 40 bytes
 */
struct libnet_ipv6_hdr
{
    u_int8_t ip_flags[4];     /* version, traffic class, flow label */
    u_int16_t ip_len;         /* total length */
    u_int8_t ip_nh;           /* next header */
    u_int8_t ip_hl;           /* hop limit */
    struct libnet_in6_addr ip_src, ip_dst; /* source and dest address */

};

/*
 *  IPv6 frag header
 *  Internet Protocol, version 6
 *  Static header size: 8 bytes
 */
#define LIBNET_IPV6_NH_FRAGMENT 44
struct libnet_ipv6_frag_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_reserved;    /* reserved */
    u_int16_t ip_frag;       /* fragmentation stuff */
    u_int32_t ip_id;         /* id */
};

/*
 *  IPv6 routing header
 *  Internet Protocol, version 6
 *  Base header size: 4 bytes
 */
#define LIBNET_IPV6_NH_ROUTING  43
struct libnet_ipv6_routing_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    u_int8_t ip_rtype;       /* routing type */
    u_int8_t ip_segments;    /* segments left */
    /* routing information allocated dynamically */
};

/*
 *  IPv6 destination options header
 *  Internet Protocol, version 6
 *  Base header size: 2 bytes
 */
#define LIBNET_IPV6_NH_DESTOPTS 60
struct libnet_ipv6_destopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};

/*
 *  IPv6 hop by hop options header
 *  Internet Protocol, version 6
 *  Base header size: 2 bytes
 */
#define LIBNET_IPV6_NH_HBH      0
struct libnet_ipv6_hbhopts_hdr
{
    u_int8_t ip_nh;          /* next header */
    u_int8_t ip_len;         /* length of header in 8 octet units (sans 1st) */
    /* destination options information allocated dynamically */
};

/*
 *  ICMP6 header
 *  Internet Control Message Protocol v6
 *  Base header size: 8 bytes
 */
#ifndef IPPROTO_ICMP6
#define IPPROTO_ICMP6   0x3a
#endif
struct libnet_icmpv6_hdr
{
    u_int8_t icmp_type;       /* ICMP type */
#ifndef ICMP6_ECHO
#define ICMP6_ECHO          128
#endif
#ifndef ICMP6_ECHOREPLY
#define ICMP6_ECHOREPLY     129
#endif
#ifndef ICMP6_UNREACH
#define ICMP6_UNREACH       1
#endif
#ifndef ICMP6_PKTTOOBIG
#define ICMP6_PKTTOOBIG     2
#endif
#ifndef ICMP6_TIMXCEED
#define ICMP6_TIMXCEED      3
#endif
#ifndef ICMP6_PARAMPROB
#define ICMP6_PARAMPROB     4
#endif
    u_int8_t icmp_code;       /* ICMP code */
    u_int16_t icmp_sum;       /* ICMP Checksum */
    u_int16_t id;             /* ICMP id */
    u_int16_t seq;            /* ICMP sequence number */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

#endif  /* __LIBNET_HEADERS_H */

/* EOF */

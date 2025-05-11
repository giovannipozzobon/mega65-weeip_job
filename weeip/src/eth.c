/**
 * @file eth.c
 * @brief Ethernet management for the MEGA65 45GS100 integrated 100mbit Ethernet controller
 * @compiler CC65
 * @author Paul Gardner-Stephen (paul@m-e-g-a.org)
 * Based on code by: 
 * @author Bruno Basseto (bruno@wise-ware.org)
 */

#include <stdio.h>
#include <stdint.h>

#include <string.h>

#include "../include/task.h"
#include "../include/weeip.h"
#include "../include/arp.h"
#include "../include/eth.h"

#include "../../mega65/include/memory.h"
#include "../../mega65/include/hal.h"
#include "../../mega65/include/debug.h"
#include "../../mega65/include/time.h"

#define MEGA65_ETH_CTRL1        0xD6E0
#define MEGA65_ETH_CTRL2        0xD6E1
#define MEGA65_ETH_TXSIZE_LSB   0xD6E2
#define MEGA65_ETH_TXSIZE_MSB   0xD6E3
#define MEGA65_ETH_COMMAND      0xD6E4
#define MEGA65_ETH_CTRL3        0xD6E5

#define MEGA65_VICII_RSTR_CMP   0xD012

#define _PROMISCUOUS

// #define NOCRCCHECK

unsigned char eth_log_mode=0;

static uint16_t eth_size;        // Packet size.
uint16_t eth_tx_len=0;           // Bytes written to TX buffer


IPV4 ip_mask;                       ///< Subnetwork address mask.
IPV4 ip_gate;                       ///< IP Gateway address.
IPV4 ip_dnsserver;                  ///< DNS Server IP

/**
 * Ethernet frame header.
 */
typedef struct {
   EUI48 destination;            ///< Packet Destination address.
   EUI48 source;                 ///< Packet Source address.
   uint16_t type;                ///< Packet Type or Size (big-endian)
} ETH_HEADER;

/**
 * Ethernet frame header buffer.
 */
ETH_HEADER eth_header;

/**
 * Local MAC address.
 */
EUI48 mac_local;

void wait_100ms(void);

#define MTU 2048
unsigned char tx_frame_buf[MTU];

void eth(uint8_t b)
{
  if (eth_tx_len<MTU) tx_frame_buf[eth_tx_len]=b;
  eth_tx_len++;
}

/*
 * Check if the transceiver is ready to transmit a packet.
 * @return TRUE if a packet can be sent.
 */
bool_t
eth_clear_to_send()
{
    // now test that TXRST (bit7) really is set
    if (PEEK(MEGA65_ETH_CTRL1) & 0x80) {
        return TRUE;
    }

    POKE(MEGA65_ETH_CTRL1, PEEK(MEGA65_ETH_CTRL1) | 0x80);

    wait_100ms();

    return (PEEK(MEGA65_ETH_CTRL1) & 0x80) != 0;
    //return FALSE;
}

/**
 * Command the ethernet controller to discard the current frame in the
 * RX buffer.
 * Select next one, if existing.
 */
void 
eth_drop()
{
  // Do nothing, as we pop the ethernet buffer off when asking for a frame in
  // eth_task().
  
}

char dbg_msg[80];
unsigned char sixteenbytes[16];

/**
 * Ethernet control task.
 * Shall be called when a packet arrives.
 */
uint16_t frame_count=0;

void eth_process_frame(void)
{  
  unsigned short i;
  unsigned char j=PEEK(0xD6EF);
  struct m65_tm tm;
 
  unsigned char cpu_side=j&3;
  unsigned char eth_side=(j>>2)&3;

  // Acknowledge the ethernet frame, freeing the buffer up for next RX
  POKE(MEGA65_ETH_CTRL2,0x01); POKE(MEGA65_ETH_CTRL2,0x03);

  //  printf("/");
  
  // Process the next received ethernet frame
  
  /*
   * A packet is available.
   */

#if 0
  // XXX DEBUG: Record all received frames in attic RAM for comparison
  lcopy(ETH_RX_BUFFER,0x8400000L+(frame_count*2048L),2048);
  lpoke(0x87ffffe,frame_count);
  lpoke(0x87fffff,frame_count>>8);
  frame_count++;

  {
    int len =lpeek(ETH_RX_BUFFER+0L)+256*(lpeek(ETH_RX_BUFFER+1L)&7);
    if (len>1000) printf("/%d/",len);
  }
#endif
  
  if (eth_log_mode&ETH_LOG_RX) {
    getrtc(&tm);
    debug_msg("");
    snprintf(dbg_msg,80,"%02d:%02d:%02d/%d eth rx\n",tm.tm_hour,tm.tm_min,tm.tm_sec,PEEK(MEGA65_VICII_RSTR_CMP));
    debug_msg(dbg_msg);
    for(i=0;i<2048;i+=16) {
      lcopy(ETH_RX_BUFFER+i,(unsigned long)sixteenbytes,16);
      snprintf(dbg_msg,80,"  %04x : ",i);
      for(j=0;j<16;j++) snprintf(&dbg_msg[strlen(dbg_msg)],80-strlen(dbg_msg)," %02x",sixteenbytes[j]);
      debug_msg(dbg_msg);
    }
  }
  
  // +2 to skip length and flags field
  lcopy(ETH_RX_BUFFER+2L,(uint32_t)&eth_header, sizeof(eth_header));
  
  /*
   * Check destination address.
   */

  if((eth_header.destination.b[0] &
      eth_header.destination.b[1] &
      eth_header.destination.b[2] &
      eth_header.destination.b[3] &
      eth_header.destination.b[4] &
      eth_header.destination.b[5]) != 0xff) {
    /*
     * Not broadcast, check if it matches the local address.
     */
    if(memcmp(&eth_header.destination, &mac_local, sizeof(EUI48)))
      goto drop;
  }
  
  /*
   * Address match, check protocol.
   * Read protocol header.
   */
  if(eth_header.type == 0x0608) {            // big-endian for 0x0806
    /*
     * ARP packet.
     */
    lcopy(ETH_RX_BUFFER+2+14,(uint32_t)&_header, sizeof(ARP_HDR));
    arp_mens();   
    goto drop;
  }
  else if(eth_header.type == 0x0008) {            // big-endian for 0x0800
    /*
     * IP packet.
     * Verify transport protocol to load header.
     */
    
/*    lcopy(ETH_RX_BUFFER+2+14,(uint32_t)&_header, sizeof(IP_HDR));
    update_cache(&_header.ip.source, &eth_header.source);
    switch(_header.ip.protocol) {
      case IP_PROTO_UDP:
        lcopy(ETH_RX_BUFFER+2+14+sizeof(IP_HDR),(uint32_t)&_header.t.udp, sizeof(UDP_HDR));
        break;
      case IP_PROTO_TCP:
        lcopy(ETH_RX_BUFFER+2+14+sizeof(IP_HDR),(uint32_t)&_header.t.tcp, sizeof(TCP_HDR));
        break;
      case IP_PROTO_ICMP:
        lcopy(ETH_RX_BUFFER+2+14+sizeof(IP_HDR),(uint32_t)&_header.t.icmp, sizeof(ICMP_HDR));
        break;
      default:
        goto drop;
    }
*/

{
    /* 1) Compute where the IP header lives in the RX buffer */
    unsigned long base_offset     = (unsigned long)ETH_RX_BUFFER + 2UL;
    unsigned long eth_hdr_size    = (unsigned long)sizeof(ETH_HEADER);
    unsigned long ip_hdr_offset   = base_offset + eth_hdr_size;
    unsigned long ip_hdr_size     = (unsigned long)sizeof(IP_HDR);

    /* 2) Copy the IP header into our _header struct */
    lcopy(
      ip_hdr_offset,               /* source in RX buffer */
      (unsigned long)&_header,     /* destination in RAM */
      ip_hdr_size                  /* how many bytes to copy */
    );

    /* 3) Update ARP cache from the IP source/MAC */
    update_cache(&_header.ip.source, &eth_header.source);

    /* 4) Compute where the transport header begins */
    unsigned long trans_offset    = ip_hdr_offset + ip_hdr_size;

    /* 5) Compute the address in RAM where that payload should go */
    unsigned char *hdr_ptr        = (unsigned char *)&_header;
    unsigned long  trans_addr     = (unsigned long)(hdr_ptr + ip_hdr_size);

    /* 6) Dispatch based on protocol */
    switch (_header.ip.protocol) {
      case IP_PROTO_UDP:
        lcopy(trans_offset, trans_addr, (unsigned long)sizeof(UDP_HDR));
        break;

      case IP_PROTO_TCP:
        lcopy(trans_offset, trans_addr, (unsigned long)sizeof(TCP_HDR));
        break;

      case IP_PROTO_ICMP:
        lcopy(trans_offset, trans_addr, (unsigned long)sizeof(ICMP_HDR));
        break;

      default:
        goto drop;
    }
}




    nwk_downstream();
  }
  else {
    //    printf("Unknown ether type $%04x\n",eth_header.type);
  }
  
 drop:
  eth_drop(); 
}

uint8_t eth_task (unsigned char p)
{
  /*
   * Check if there are incoming packets.
   * If not, then check in a while.
   */
  unsigned char frames=0;
  uint8_t delay=0;

  // Process multiple ethernet frames at a time
  while((PEEK(MEGA65_ETH_CTRL2)&0x20)) {
    //    printf("[%d]",frames);
    eth_process_frame();
    frames++;
    if (frames==32) break;
  }
  
  // Check the RXIRQ flag to see if we have frames waiting or not
  if(!(PEEK(MEGA65_ETH_CTRL2)&0x20)) {
    delay = 10;
  }
  task_add(eth_task, delay, 0, "ethtask");
  return 0;
}

#define IPH(X) _header.ip.X

void eth_write(localbuffer_t buf,uint16_t len)
{
  if (len+eth_tx_len>=MTU) return;
  lcopy((uint32_t)buf,(unsigned long)&tx_frame_buf[eth_tx_len],len);
  eth_tx_len+=len;
}

/**
 * Finish transfering an IP packet to the ethernet controller and start transmission.
 */
void eth_packet_send(void)
{
  unsigned short i;
  unsigned char j;
  struct m65_tm tm;

  

  // Set packet length
  mega65_io_enable();
  POKE(MEGA65_ETH_TXSIZE_LSB,eth_tx_len&0xff);
  POKE(MEGA65_ETH_TXSIZE_MSB,eth_tx_len>>8);

  // Copy our working frame buffer to 
  lcopy((unsigned long)tx_frame_buf,ETH_TX_BUFFER,eth_tx_len);

  if (eth_log_mode&ETH_LOG_TX) {
    getrtc(&tm);
    debug_msg("");
    snprintf(dbg_msg,80,"%02d:%02d:%02d/%d eth tx\n",tm.tm_hour,tm.tm_min,tm.tm_sec,PEEK(MEGA65_VICII_RSTR_CMP));
    debug_msg(dbg_msg);
    for(i=0;i<eth_tx_len;i+=16) {
      snprintf(dbg_msg,80,"  %04x : ",i);
      for(j=0;j<16;j++) snprintf(&dbg_msg[strlen(dbg_msg)],80-strlen(dbg_msg)," %02x",tx_frame_buf[i+j]);
      debug_msg(dbg_msg);
    }
  }
  

  
#if 0
  printf("ETH TX: %x:%x:%x:%x:%x:%x\n",
	 tx_frame_buf[0],tx_frame_buf[1],tx_frame_buf[2],tx_frame_buf[3],tx_frame_buf[4],tx_frame_buf[5]
	 );
#endif
  
  // Make sure ethernet is not under reset
  POKE(MEGA65_ETH_CTRL1,0x03);
    
  // Send packet
  POKE(MEGA65_ETH_COMMAND,0x01); // TX now
}


/**
 * Start transfering an IP packet.
 * Find MAC address and send headers to the ethernet controller.
 * @return TRUE if succeeded.
 */
bool_t 
eth_ip_send()
{
   static IPV4 ip;
   static EUI48 mac;

   if(!eth_clear_to_send()) {
     return FALSE;               // another transmission in progress, fail.
   }

   /*
    * Check destination IP.
    */
   ip.d = IPH(destination).d;
   if(ip.d != 0xffffffff) {                        // is it broadcast?
      if(ip_mask.d & (ip.d ^ ip_local.d))          // same network?
	{
	  ip.d = ip_gate.d;                         // send to gateway for reaching other networks.
	}
   }

   if(!query_cache(&ip, &mac)) {                   // find MAC
      arp_query(&ip);                              // yet unknown IP, query MAC and fail.
      //      printf("A");
      return FALSE;
   }

   /*
    * Send ethernet header.
    */
   eth_tx_len=0;

   eth_write((uint8_t*)&mac, 6);
   eth_write((uint8_t*)&mac_local, 6);
   eth(0x08);                                      // type = IP (0x0800)
   eth(0x00);

   /*
    * Send protocol header.
    */
   if(IPH(protocol) == IP_PROTO_UDP) eth_size = 28;    // header size
   else eth_size = sizeof(HEADER);
   eth_write((uint8_t*)&_header, eth_size);
   
   //   printf("eth_ip_send success.\n");
   return TRUE;
}

/**
 * Send an ARP packet.
 * @param mac Destination MAC address.
 */
void 
eth_arp_send
   (EUI48 *mac)
{
  if(!(PEEK(MEGA65_ETH_CTRL1)&0x80)) return;                     // another transmission in progress.
   
   eth_tx_len=0;

   eth_write((uint8_t*)mac, 6);
   eth_write((uint8_t*)&mac_local, 6);
   eth(0x08);                                      // type = ARP (0x0806)
   eth(0x06);

   /*
    * Send protocol header.
    */
   eth_write((uint8_t*)&_header, sizeof(ARP_HDR));
   
   /*
    * Start transmission.
    */
   eth_packet_send();
}

void wait_100ms(void)
{
  // 16 x ~64usec raster lines = ~1ms
  int c = 1600;
  unsigned char b;
  while (c--) {
    b = PEEK(MEGA65_VICII_RSTR_CMP);
    while (b == PEEK(MEGA65_VICII_RSTR_CMP))
      continue;
  }
}

/**
 * Ethernet controller initialization and configuration.
 */
void
eth_init()
{
   unsigned char timer = 40;
   eth_drop();

   /*
    * Setup frame reception filter.
    */
#if defined(_PROMISCUOUS)
   POKE(MEGA65_ETH_CTRL3,PEEK(MEGA65_ETH_CTRL3)&0xFE);
#else
   POKE(MEGA65_ETH_CTRL3,PEEK(MEGA65_ETH_CTRL3)|0x01);
#endif
#ifdef NOCRCCHECK
   POKE(MEGA65_ETH_CTRL3,PEEK(MEGA65_ETH_CTRL3)|0x02);
#else
   POKE(MEGA65_ETH_CTRL3,PEEK(MEGA65_ETH_CTRL3)&0xfd);
#endif


   // Set ETH TX Phase to 1
   POKE(MEGA65_ETH_CTRL3,(PEEK(MEGA65_ETH_CTRL3)&0xf3)|(1<<2));   

   // Set ETH RX Phase delay to 1
   POKE(MEGA65_ETH_CTRL3,(PEEK(MEGA65_ETH_CTRL3)&0x3f)|(1<<6));   
   
   /*
    * Read MAC address from ETH controller
    */
   lcopy(0xFFD36E9,(unsigned long)&mac_local.b[0],6);

   /* Reset, then release from reset and reset TX FSM
      Note: The datasheet claims that 500usec after 0, and 100usec after
      writing 3 should be sufficient.
      But my experimentation suggests that 100ms for each is required instead.
    */
   POKE(MEGA65_ETH_CTRL1,0);
   wait_100ms();
   POKE(MEGA65_ETH_CTRL1,3);
   wait_100ms();
   POKE(MEGA65_ETH_CTRL2,3);
   POKE(MEGA65_ETH_CTRL2,0);
   // wait four seconds to allow PHY to come up again
   while (timer--)
     wait_100ms();
   
   // XXX Enable ethernet IRQs?
}

/**
 * Disable ethernet controller.
 */
void eth_disable()
{
   /*
    * Wait for any pending activity.
    */
   // XXX Disable ethernet IRQs?
}


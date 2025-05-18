/**
 * @file nwk.c
 * @brief Network and Transport layers.
 * @compiler CC65
 * @author Paul Gardner-Stephen (paul@m-e-g-a.org)
 * derived from:
 * @author Bruno Basseto (bruno@wise-ware.org)
 */

 #include <stdio.h>

 #include <stdint.h>
 
 #include "../../mega65/include/memory.h"
 
 #include "../../mega65/include/debug.h"
 
 // On MEGA65 we have deep enough stack we don't need to schedule sending
 // ACKs, we can just send them immediately.
 // #define INSTANT_ACK
 // Report various things on serial monitor interface
 // #define DEBUG_ACK
 
 // #define DEBUG_TCP_REASSEMBLY
 
 // Enable ICMP PING if desired.
 #define ENABLE_ICMP
 
 /*
   Use a graduated timeout that starts out fast, and then slows down,
   so that we spread our timeouts over a longer preiod of time, but
   at the same time, we don't wait forever for initial retries on a
   local LAN
 */
 #define SOCKET_TIMEOUT(S)(TIMEOUT_TCP + 8 * (RETRIES_TCP - S -> retry))
 //#define DEBUG_TCP_RETRIES
 
 /********************************************************************************
  ********************************************************************************
  * The MIT License (MIT)
  *
  * Copyright (c) 1995-2013 Bruno Basseto (bruno@wise-ware.org).
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in
  * all copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  * THE SOFTWARE.
  ********************************************************************************
  ********************************************************************************/
 
 #include <string.h>
 
 #include "../include/weeip.h"
 
 #include "../include/checksum.h"
 
 #include "../include/eth.h"
 
 #include "../include/arp.h"
 
 /**
  * Message header buffer.
  */
 HEADER _header;
 
 IPV4 ip_broadcast; ///< Subnetwork broadcast address
 
 extern char dbg_msg[80];
 
 static uint16_t data_size, data_ofs;
 static _uint32_t seq;
 #define TCPH(X) _header.t.tcp.X
 #define ICMPH(X) _header.t.icmp.X
 #define UDPH(X) _header.t.udp.X
 #define IPH(X) _header.ip.X
 
 // Smaller MTU to save memory
 #define MTU 1000
 extern unsigned char tx_frame_buf[MTU];
 extern unsigned short eth_tx_len;
 
 /**
  * Packet counter.
  */
 uint16_t id;
 
 /**
  * Local IP address.
  */
 IPV4 ip_local;
 
 /**
  * Default header.
  */
 #define WINDOW_SIZE_OFFSET 34
 byte_t default_header[HEADER_LEN] = {
  // IP header
  0x45, 0x08, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

  // UDP/TCP header
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,
  // TCP header length field
  ((HEADER_LEN - 20) & 0xfc) << 2,
  0x00,
  // TCP Window size
  0xff, 0xff, // ~64KB by default
  0x00, 0x00, 0x00, 0x00,
  // TCP option bytes reservation
  #if HEADER_LEN == 56
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  #endif
  #if HEADER_LEN == 64
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  #endif   
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
 };
 
 /**
  * Flags received within last packet.
  */
 byte_t _flags;
 
 void remove_rx_data(SOCKET * _sckt);
 
 void tcp_bytes(char c) {
   #ifdef DEBUG_TCP_REASSEMBLY
   snprintf(dbg_msg, 80, "   delivering %ld tcp payload bytes (%c)",
     _sckt -> rx_data, c);
   debug_msg(dbg_msg);
   #endif
 }
 
 /**
  * TCP timing control task.
  * Called periodically at a rate defined by TICK_TCP.
  */
 byte_t nwk_tick(byte_t sig) {
   static byte_t t = 0;
 
   /*
    * Loop all sockets.
    */
   for_each(_sockets, _sckt) {
     if (_sckt -> type != SOCKET_TCP) continue; // UDP socket or unused.
     if(_sckt->time == 0) continue;                        // does not have timing requirements.
 
     if (_sckt->rx_data == 0 && _sckt->state == _CONNECT && !_sckt->timeout) {
      _sckt->toSend = ACK;
      _sckt->timeout = TRUE;
      task_cancel(nwk_upstream);
      task_add(nwk_upstream, 0, 0, "upstream");
      continue;
    }

     /*
      * Do socket timing.
      */
     if (_sckt -> time) _sckt -> time--;
     if (_sckt -> time == 0) {
       /*
        * Timeout.
        * Check retransmissions.
        */
       if (_sckt -> retry) {
         #ifdef DEBUG_TCP_RETRIES
         printf("tcp retry %d\n", _sckt -> retry);
         #endif
         _sckt -> retry--;
         _sckt -> time = SOCKET_TIMEOUT(_sckt);
         switch (_sckt -> state) {
         case _SYN_SENT:
         case _ACK_REC:
           _sckt -> toSend = SYN;
           break;
         case _SYN_REC:
           _sckt -> toSend = SYN | ACK;
           break;
         case _ACK_WAIT:
           _sckt -> toSend = ACK | PSH;
           break;
         case _FIN_SENT:
         case _FIN_ACK_REC:
           _sckt -> toSend = ACK;
           #ifdef DEBUG_ACK
           debug_msg("Asserting ACK: _FIN_ACK_REC state");
           #endif
           break;
         case _FIN_REC:
           _sckt -> toSend = FIN | ACK;
           #ifdef DEBUG_ACK
           debug_msg("Asserting ACK: _FIN_REC state");
           #endif
           break;
         default:
           _sckt -> toSend = ACK;
           _sckt -> time = SOCKET_TIMEOUT(_sckt);
           _sckt -> timeout = FALSE;
           break;
         }
         if (_sckt -> toSend) {
           /*
            * Force nwk_upstream() to execute.
            */
           _sckt -> timeout = TRUE;
           #ifdef INSTANT_ACK
           nwk_upstream(0);
           #endif
           #ifdef DEBUG_ACK
           debug_msg("scheduling nwk_upstream 0 0");
           #endif
           task_cancel(nwk_upstream);
           task_add(nwk_upstream, 0, 0, "upstream");
         }
       } else {
         /*
          * Too much retransmissions.
          * Socket down.
          */
         _sckt -> state = _IDLE;
         tcp_bytes('d');
 
         _sckt -> callback(WEEIP_EV_DISCONNECT);
         remove_rx_data(_sckt);
       }
     }
   }
 
   /*
    * Reschedule task for periodic execution.
    */
   task_add(nwk_tick, TICK_TCP, 0, "nwktick");
   return 0;
 }
 
 void remove_rx_data(SOCKET * _sckt) {
   unsigned short n;
 
   if (!_sckt -> rx_data) {
     return;
   }
 
   #ifdef DEBUG_TCP_REASSEMBLY
   snprintf(dbg_msg, 80, "   shuffling down %ld bytes. oo_start,end was %ld,%ld.",
     _sckt -> rx_data, _sckt -> rx_oo_start, _sckt -> rx_oo_end);
   debug_msg(dbg_msg);
   #endif
 
   // We are removing rx_data, so need to shuffle the out-of-order assembly
   // area down that far.
 
   if (_sckt -> rx_oo_end > _sckt -> rx_data) {
 
     uint32_t ofs, n;
 
     n = _sckt -> rx_oo_end - _sckt -> rx_data;
 
     for (ofs = 0; ofs < n; ofs += 65535L) {
 
       uint32_t count = 65535L;
       if (count > (n - ofs)) count = n - ofs;
 
       // Copy down from the end of the received data to rx_oo_end.
       lcopy(_sckt -> rx + _sckt -> rx_data + ofs, _sckt -> rx + ofs, n);
     }
 
     if (_sckt -> rx_oo_start > _sckt -> rx_data)
       _sckt -> rx_oo_start -= _sckt -> rx_data;
     else
       _sckt -> rx_oo_start = 0;
 
     _sckt -> rx_oo_end -= _sckt -> rx_data;
 
   }
   _sckt -> rx_data = 0;
 
   #ifdef DEBUG_TCP_REASSEMBLY
   snprintf(dbg_msg, 80, "   shuffled down oo_start,end now %ld,%ld.",
     _sckt -> rx_oo_start, _sckt -> rx_oo_end);
   debug_msg(dbg_msg);
   #endif
 
 }
 
 void compute_window_size(SOCKET * _sckt) {
   uint32_t available_window = 0;
   // Now patch the header to take account of how much buffer space we _actually_ have available
   available_window = _sckt -> rx_size - _sckt -> rx_data;
   if (available_window > 0xffff) available_window = 0xffff;
 
   //  printf("\n[Window=%ld,sz=%ld,used=%ld]\n",available_window,_sckt->rx_size,_sckt->rx_data);
 
   default_header[WINDOW_SIZE_OFFSET + 0] = available_window >> 8;
   default_header[WINDOW_SIZE_OFFSET + 1] = available_window >> 0;
 }
 
 /**
  * Network upstream task. Send outgoing network messages.
  */
 byte_t nwk_upstream(byte_t sig) {
 
   #ifdef DEBUG_ACK
   debug_msg("nwk_upstream called.");
   #endif

//snprintf(dbg_msg, 80,"upstream: clear=%d toSend=%d retry=%d\r", eth_clear_to_send(), _sckt->toSend, _sckt->retry);
//debug_msg(dbg_msg);
//printf("D6E0=%02x\r", PEEK(0xD6E0));

//uint8_t _stall = 0;

   if (eth_clear_to_send() == FALSE) {
     /*
      * Ethernet not ready.
      * Delay task execution.
      */
     #ifdef DEBUG_ACK
     debug_msg("scheduling nwk_upstream 2 0");
     #endif

//     if (++_stall > 50) return 0;

     task_add(nwk_upstream, 2, 0, "upstream");
     return 0;
   }
 
   /*
    * Search for pending messages.
    */
   for_each(_sockets, _sckt) {
     if (!_sckt -> toSend) continue; // no message to send for this socket.
 
     #ifdef DEBUG_ACK
     debug_msg("nwk_upstream sending a packet for socket");
     #endif
 
     /*
      * Pending message found, send it.
      */
     checksum_init();
 
     compute_window_size(_sckt);
 
     // XXX Correct buffer offset processing to handle variable
     // header lengths
     lcopy((uint32_t) default_header, (uint32_t) _header.b, HEADER_LEN);
 
     IPH(id) = HTONS(id);
     id++;
 
     IPH(source).d = ip_local.d;
     IPH(destination).d = _sckt -> remIP.d;
     TCPH(source) = _sckt -> port;
     TCPH(destination) = _sckt -> remPort;
 
     /*
      * Check payload area in _sckt->tx.
      */
     if (_sckt -> toSend & PSH) {
       data_size = _sckt -> tx_size;
       ip_checksum((byte_t * ) _sckt -> tx, data_size);
     } else data_size = 0;
 
     if (_sckt -> type == SOCKET_TCP) {
       /*
        * TCP message header.
        */
       // 56 = 20 for IP header plus 36 for TCP header (including 16 bytes reserved for TCP options)
       IPH(length) = HTONS((HEADER_LEN + data_size));
       TCPH(flags) = _sckt -> toSend;
 
       /*
        * Check sequence numbers.
        */
       seq.d = _sckt -> seq.d;
       if (_sckt -> timeout) {
         /*
          * Retransmission.
          * Use old sequence number.
          */
         if (data_size) seq.d -= data_size;
       }
 
       TCPH(n_seq).b[0] = seq.b[3];
       TCPH(n_seq).b[1] = seq.b[2];
       TCPH(n_seq).b[2] = seq.b[1];
       TCPH(n_seq).b[3] = seq.b[0];
       TCPH(n_ack).b[0] = _sckt -> remSeq.b[3];
       TCPH(n_ack).b[1] = _sckt -> remSeq.b[2];
       TCPH(n_ack).b[2] = _sckt -> remSeq.b[1];
       TCPH(n_ack).b[3] = _sckt -> remSeq.b[0];
 
       if (_sckt -> toSend & SYN) {
         // Negotiate MSS during connection establishment.
         TCPH(options[0]) = 0x02;
         TCPH(options[1]) = 0x04;
         // Limit to 1300 like google does, so that tunnelled and double-tunnelled connections work
         TCPH(options[2]) = 1300 >> 8;
         TCPH(options[3]) = (1300 & 0xff);
         if (HEADER_LEN >= (40 + 2 + 8 + 8)) {
           // Permit Selective Acknowledgement (SACK)
           TCPH(options[4]) = 0x04;
           TCPH(options[5]) = 0x02;
         }
       } else {
         // Include SACK records.
         // 2 byte header + 8 bytes per record
         // 24 bytes thus gets us 2 SACK records
         if ((HEADER_LEN - 40) >= (2 + 8)) {
           if (_sckt -> rx_oo_start) {
             TCPH(options[0]) = 0x05;
             TCPH(options[1]) = 0x02 + 8;
             TCPH(options[2]) = (_sckt -> rx_oo_start + _sckt -> remSeq.d) >> 24;
             TCPH(options[3]) = (_sckt -> rx_oo_start + _sckt -> remSeq.d) >> 16;
             TCPH(options[4]) = (_sckt -> rx_oo_start + _sckt -> remSeq.d) >> 8;
             TCPH(options[5]) = (_sckt -> rx_oo_start + _sckt -> remSeq.d) >> 0;
             TCPH(options[6]) = (_sckt -> rx_oo_end + _sckt -> remSeq.d) >> 24;
             TCPH(options[7]) = (_sckt -> rx_oo_end + _sckt -> remSeq.d) >> 16;
             TCPH(options[8]) = (_sckt -> rx_oo_end + _sckt -> remSeq.d) >> 8;
             TCPH(options[9]) = (_sckt -> rx_oo_end + _sckt -> remSeq.d) >> 0;
           }
         }
       }
 
       if (_sckt -> remSeq.d - _sckt -> remSeqStart.d) {
         #if 0
         snprintf(dbg_msg, 80, "[ACK %ld]  ",
           _sckt -> remSeq.d - _sckt -> remSeqStart.d + data_size);
         #endif
 
         if (!_sckt -> timeout) {
           /*
            * Update sequence number data.
            */
           if (data_size) seq.d += data_size;
           if (_sckt -> toSend & (SYN | FIN)) seq.d++;
           if ((_sckt -> toSend & (SYN | ACK)) == (SYN | ACK)) seq.d++;
           _sckt -> seq.d = seq.d;
         }
       }
 
       /*
        * Update TCP checksum information.
        */
       TCPH(checksum) = 0;
       ip_checksum( & _header.b[12], sizeof(TCP_HDR));
       add_checksum(IP_PROTO_TCP);
       add_checksum(data_size + sizeof(TCP_HDR));
       TCPH(checksum) = checksum_result();
     } else {
       /*
        * UDP message header.
        */
 
       IPH(protocol) = IP_PROTO_UDP;
       IPH(length) = HTONS((28 + data_size));
       UDPH(length) = HTONS((8 + data_size));
 
       /*
        * Update UDP checksum information.
        */
       UDPH(checksum) = 0;
       ip_checksum( & _header.b[12], 8 + sizeof(UDP_HDR));
       add_checksum(IP_PROTO_UDP);
       add_checksum(data_size + sizeof(UDP_HDR));
       UDPH(checksum) = checksum_result();
 
       /*
        * Tell UDP that data was sent (no acknowledge).
        */
 
       _sckt -> callback(WEEIP_EV_DATA_SENT);
       remove_rx_data(_sckt);
     }
 
     /*
      * Update IP checksum information.
      */
     checksum_init();
     ip_checksum((byte_t * ) & _header, 20);
     IPH(checksum) = checksum_result();
 
     /*
      * Send IP packet.
      */
     if (eth_ip_send()) {
       if (data_size) eth_write((byte_t * ) _sckt -> tx, data_size);
       #ifdef DEBUG_ACK
       debug_msg("eth_packet_send() called");
       #endif
       eth_packet_send();
 
       _sckt -> toSend = 0;
       _sckt -> timeout = FALSE;
       _sckt -> time = SOCKET_TIMEOUT(_sckt);
 
     } else {
       // Sending the IP packet failed, possibly because there was no ARP
       // entry for the requested IP, if it is on the local network.
 
       // So we don't clear the status that we need to send
     }
 
     /*
      * Reschedule 50ms later for eventual further processing.
      */
     #ifdef DEBUG_ACK
     debug_msg("scheduling nwk_upstream 5 0");
     #endif
     task_add(nwk_upstream, 5, 0, "upstream");
   }
 
   /*
    * Job done, finish.
    */
   return 0;
 }
 
 unsigned long byte_order_swap_d(unsigned long in ) {
   unsigned long out;
   ((unsigned char * ) & out)[0] = ((unsigned char * ) & in)[3];
   ((unsigned char * ) & out)[1] = ((unsigned char * ) & in)[2];
   ((unsigned char * ) & out)[2] = ((unsigned char * ) & in)[1];
   ((unsigned char * ) & out)[3] = ((unsigned char * ) & in)[0];
   return out;
 }
 
 void nwk_schedule_oo_ack(SOCKET * _sckt) {
   /*
    * Out of order, send our number.
    */
   #ifdef DEBUG_ACK
   printf("request OOO ack: %ld != %ld\n",
     byte_order_swap_d(TCPH(n_seq.d)) - _sckt -> remSeqStart.d, _sckt -> remSeq.d - _sckt -> remSeqStart.d);
   #endif
   _sckt -> toSend = ACK;
   #ifdef INSTANT_ACK
   nwk_upstream(0);
   #endif
   #ifdef DEBUG_ACK
   debug_msg("asserting ack: Out-of-order rx");
   debug_msg("scheduling nwk_upstream 0 0");
   #endif
   task_cancel(nwk_upstream);
   task_add(nwk_upstream, 0, 0, "upstream");
 }
 
 static inline uint16_t ntohs(uint16_t x) {
   return (x >> 8) | (x << 8);
 }
 
 /**
  * Network downstream processing.
  * Parse incoming network messages.
  */
 void nwk_downstream(void) {
   WEEIP_EVENT ev;
   _uint32_t rel_sequence;
   uint16_t rx_ip_chks;
   static unsigned char i;
 
uint8_t ip_hlen  = (IPH(ver_length) & 0x0F) << 2;        // 20…60
uint8_t tcp_hlen;

/* Make sure entire IP header (20…60 bytes) is present in _header */
if (ip_hlen > sizeof(IP_HDR))
    lcopy(ETH_RX_BUFFER + 2 + 14 + sizeof(IP_HDR),
          (uint32_t)&_header.b[sizeof(IP_HDR)],
          ip_hlen - sizeof(IP_HDR));

   ev = WEEIP_EV_NONE;
 
   /*
    * Packet size.
    */
//   if (IPH(ver_length) != 0x45) goto drop;

/* Accept any IPv4 header length (low nibble 5-15) */
if ((IPH(ver_length) & 0xF0) != 0x40)   /* version must be 4 */
    goto drop;

   data_size = NTOHS(IPH(length));
 
   /*
    * Checksum.
    */
   checksum_init();
   rx_ip_chks = IPH(checksum);
   IPH(checksum) = 0;
   ip_checksum(_header.b, ip_hlen); 
   if (rx_ip_chks != checksum_result()) goto drop;


   // early-out ICMP echo:
   if (IPH(protocol) == IP_PROTO_ICMP && ICMPH(type) == 8 && ICMPH(fcode) == 0) {

      // total IP length in host order:
      uint16_t total = NTOHS(IPH(length));    // 20 (IP hdr) + ICMP payload
      uint16_t icmp  = total - 20;

      // 1) swap MACs in place
      EUI48 tmp_mac;
      lcopy(ETH_RX_BUFFER+2, (uint32_t)&tmp_mac, 6);
      lcopy(ETH_RX_BUFFER+2 + 6, (uint32_t)(ETH_RX_BUFFER+2), 6);
      lcopy((uint32_t)&tmp_mac,   (uint32_t)(ETH_RX_BUFFER+2 + 6), 6);

      // 2) swap IPs in our _header struct
      uint32_t tmp_ip = IPH(source).d;
      IPH(source).d     = IPH(destination).d;
      IPH(destination).d = tmp_ip;

      // 3) flip the ICMP type
      ICMPH(type) = 0;       // Echo Reply
      ICMPH(fcode) = 0;

      // 4) recompute ICMP checksum
      ICMPH(checksum) = 0;
      checksum_init();
      ip_checksum((byte_t*)&_header.t.icmp, icmp);
      ICMPH(checksum) = checksum_result();

      // 5) recompute IP header checksum
      IPH(checksum) = 0;
      checksum_init();
      ip_checksum(_header.b, 20);
      IPH(checksum) = checksum_result();

      // 6) push it through the normal IP transmit pipeline
      if (eth_clear_to_send()) {
         eth_ip_send();                   // writes Ethernet+IP header from _header.b
         eth_write((byte_t*)&_header.t.icmp, icmp);  
         eth_packet_send();
      }

      return;   // done — don’t fall through into your socket logic

 }
 
   #if 0
   printf("\nI am %d.%d.%d.%d\n", ip_local.b[0], ip_local.b[1], ip_local.b[2], ip_local.b[3]);
   printf("P=%02x: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
     IPH(protocol),
     IPH(source).b[0], IPH(source).b[1], IPH(source).b[2], IPH(source).b[3],
     NTOHS(TCPH(source)),
     IPH(destination).b[0], IPH(destination).b[1], IPH(destination).b[2], IPH(destination).b[3],
     NTOHS(TCPH(destination)));
   #endif
   /*
    * Destination address.
    */
   if (IPH(destination).d != 0xffffffffL) // broadcast.
     if (IPH(destination).d != ip_local.d) // unicast.
       if (IPH(destination).d != ip_broadcast.d) // unicast.
         if (ip_local.d != 0x0000000L) // Waiting for DHCP configuration
           goto drop;
   // not for us.
   /*
   printf("RX IP packet: proto=%d, src=%d.%d.%d.%d → dst=%d.%d.%d.%d\r\n",
     IPH(protocol),
     IPH(source).b[0], IPH(source).b[1], IPH(source).b[2], IPH(source).b[3],
     IPH(destination).b[0], IPH(destination).b[1], IPH(destination).b[2], IPH(destination).b[3]
   );
 
   if (IPH(protocol) == IP_PROTO_UDP) {
     // data_size already holds total IP length (network-order → host)
     uint16_t udp_len = data_size - 20; // strip 20-byte IP header
     // Access the UDP header at offset 20 from &_header
     uint16_t srcp = (_header.t.udp.source); // already big-endian in struct
     uint16_t dstp = (_header.t.udp.destination);
     printf(
       " → UDP packet: %u bytes, src port %u → dst port %u\r\n",
       udp_len,
       ntohs(srcp),
       ntohs(dstp)
     );
   }*/
 

   /*
       for_each(_sockets, _sckt) {
         if (_sckt->type == SOCKET_FREE) continue;
         int idx = _sckt - _sockets;
         // Log each candidate socket
         printf(
           "  socket[%u]: type=%u, port=%u, listening=%u\r\n",
           idx,    // or just idx if you prefer
           _sckt->type,
           ntohs(_sckt->port),
           _sckt->listening
         );
      }
       
         // Also log the packet’s dest port
         if (IPH(protocol) == IP_PROTO_UDP) {
           uint16_t dstp = ntohs(_header.t.udp.destination);
           printf("    incoming dst port = %u\r\n", dstp);
         }
   */
 
   for_each(_sockets, _sckt) {
     // 1) Skip empty slots
     if (_sckt -> type == SOCKET_FREE) continue;
 
     // 2) Only sockets you’ve bound/listened on
//     if (!_sckt -> listening) continue;
 
     // 3) Demux by protocol
     if (IPH(protocol) == IP_PROTO_UDP && _sckt -> type == SOCKET_UDP) {
       // Must match UDP and the destination port
       if (_header.t.udp.destination != _sckt -> port) continue;
       // We have a winner
       goto found;
     } else if (IPH(protocol) == IP_PROTO_TCP && _sckt -> type == SOCKET_TCP) {
       // Must match TCP and the destination port
       if (_header.t.tcp.destination != _sckt -> port) continue;
 
       // If it’s a *connected* socket (not just LISTEN), also verify peer
       if (!_sckt -> listening) {
         if (_header.t.tcp.source != _sckt -> remPort) continue;
         if (IPH(source).d != _sckt -> remIP.d) continue;
       }
       goto found;
     }
     // else: wrong protocol for this slot, keep searching
   }
 
   goto drop; // no socket for the message.
 
found:
 
   //printf("\rfound packet!!!!\r");
   _sckt -> remIP.d = IPH(source).d;
 
   if (_sckt -> type == SOCKET_UDP) {
     _sckt -> remPort = _header.t.udp.source;
     // leave listening = TRUE
   } else {
     _sckt -> remPort = TCPH(source);
     _sckt -> listening = FALSE;
   }
 
   if (IPH(protocol) == IP_PROTO_TCP) goto parse_tcp;
 
   /*
    * UDP message.
    * Copy data into user socket buffer.
    * Add task for processing.
    */
 
   data_size -= 28;
   if (_sckt -> rx) {
     if (data_size > _sckt -> rx_size) data_size = _sckt -> rx_size;
     if (data_size)
       lcopy(ETH_RX_BUFFER + 2 + 14 + sizeof(IP_HDR) + 8, _sckt -> rx, data_size);
     _sckt -> rx_data = data_size;
 
     #ifdef DEBUG_TCP_REASSEMBLY
     snprintf(dbg_msg, 80, "   set rx_data to %ld (a).", _sckt -> rx_data);
     debug_msg(dbg_msg);
     #endif
 
   }
 
   ev = WEEIP_EV_DATA;
   goto done;
 
parse_tcp:
 
/* --- compute actual header sizes --- */

tcp_hlen = (TCPH(hlen) >> 4)        << 2;        // 20…60

/* IP total length already in host order */
data_size = data_size - (ip_hlen + tcp_hlen);
if ((int16_t)data_size < 0) goto drop;     // bad packet – drop cleanly
 
     // Compute sequence relative to the current expected point
     for (i = 0; i < 4; i++) rel_sequence.b[i] = TCPH(n_seq.b[3 - i]);
   rel_sequence.d -= _sckt -> remSeq.d;
 
   /*
    * TCP message.
    * Check flags.
    */
   _flags = 0;
   // XXX - Assumes no TCP options! Fix!
   // Like it is now, it can't communicate to another instance of itself!
//   data_size -= 40;
 
   // No data to return, unless we discover otherwise
   _sckt -> rx_data = 0;
 
   #ifdef DEBUG_TCP_REASSEMBLY
   //#if 1
   snprintf(dbg_msg, 80, "saw segment [%ld,%ld), rel segment is [%ld,%ld)",
     rel_sequence.d +
     _sckt -> remSeq.d -
     _sckt -> remSeqStart.d,
 
     rel_sequence.d +
     _sckt -> remSeq.d -
     _sckt -> remSeqStart.d +
     data_size,
 
     rel_sequence.d,
     rel_sequence.d + data_size
   );
   debug_msg(dbg_msg);
   #endif
   #ifdef DEBUG_TCP_REASSEMBLY
   snprintf(dbg_msg, 80, "   (oo_start,end was %ld,%ld)",
     _sckt -> rx_oo_start, _sckt -> rx_oo_end);
   debug_msg(dbg_msg);
   #endif
 
   if (TCPH(flags) & ACK) {
     /*
      * Test acked sequence number.
      */
     if ((_sckt -> seq.b[0] != TCPH(n_ack).b[3]) ||
       (_sckt -> seq.b[1] != TCPH(n_ack).b[2]) ||
       (_sckt -> seq.b[2] != TCPH(n_ack).b[1]) ||
       (_sckt -> seq.b[3] != TCPH(n_ack).b[0])) {
       /*
        * Out of order, drop it.
        * XXX This is when the other side has ACKed a different part
        * of our stream.
        */
       if (_sckt -> state >= _CONNECT) {
         #if 0
         printf("OoO ACK %02x%02x%02x%02x vs %02x%02x%02x%02x\n",
           TCPH(n_ack).b[3],
           TCPH(n_ack).b[2],
           TCPH(n_ack).b[1],
           TCPH(n_ack).b[0],
           _sckt -> seq.b[0],
           _sckt -> seq.b[1],
           _sckt -> seq.b[2],
           _sckt -> seq.b[3]
         );
         #endif
         //	 goto drop;
       }
     }
     _flags |= ACK;
   }
 
   if (TCPH(flags) & SYN) {
     /*
      * Restart of remote sequence number (connection?).
      */
     _sckt -> remSeq.b[0] = TCPH(n_seq).b[3];
     _sckt -> remSeq.b[1] = TCPH(n_seq).b[2];
     _sckt -> remSeq.b[2] = TCPH(n_seq).b[1];
     _sckt -> remSeq.b[3] = TCPH(n_seq).b[0];
 
     // Remember initial remote sequence # for convenient debugging
     _sckt -> remSeqStart.d = _sckt -> remSeq.d;
 
     _sckt -> remSeq.d++;
     _flags |= SYN;
 
     //      printf("SYN%d",_sckt->state);
 
   } else {
     /*
      * Test remote sequence number.
      */
 
     if (data_size > _sckt -> rx_size) data_size = _sckt -> rx_size;
     // XXX Correct buffer offset processing to handle variable
     // header lengths
//     data_ofs = ((IPH(ver_length) & 0x0f) << 2) + ((TCPH(hlen) >> 4) << 2);
data_ofs = ip_hlen + tcp_hlen;             // instead of the old bit‑shift math
 
     if (rel_sequence.d > _sckt -> rx_size ||
       rel_sequence.d + data_size > _sckt -> rx_size) {
       // Ignore segments that we can't possibly handle, i.e.,
       // those that we have already ACKd, or that are beyond our window size
       if (data_size) {
         nwk_schedule_oo_ack(_sckt);
         goto drop;
       }
     } else if (rel_sequence.d == _sckt -> rx_data) {
       // Data is exactly for where we are up to: Copy to end of data in RX buffer       
       #ifdef DEBUG_TCP_REASSEMBLY
       snprintf(dbg_msg, 80, "   appending %d bytes.",
         data_size
       );
       debug_msg(dbg_msg);
       #endif
 
       if (data_size + _sckt -> rx_data > _sckt -> rx_size)
         data_size = _sckt -> rx_size - _sckt -> rx_data;
       if (data_size) {
         lcopy(ETH_RX_BUFFER + 16 + data_ofs, _sckt -> rx + _sckt -> rx_data, data_size);
       }
       _sckt -> rx_data += data_size;
 
       // Does the bytes we have now overlap with the OO area? and if so, does this mean
       // we have more bytes we can deliver now?
       if ((_sckt -> rx_data >= _sckt -> rx_oo_start) && (_sckt -> rx_oo_end > _sckt -> rx_data)) {
         // It now overlaps with our OO area: so return it all
         _sckt -> rx_data = _sckt -> rx_oo_end;
         _sckt -> rx_oo_start = 0;
         _sckt -> rx_oo_end = 0;
       }
       #ifdef DEBUG_TCP_REASSEMBLY
       snprintf(dbg_msg, 80, "   set rx_data to %ld (b).", _sckt -> rx_data);
       debug_msg(dbg_msg);
       #endif
 
       // Finally, we should reset our retry timer and schedule an ACK, so that
       // the other side knows where we are up  to
       _sckt -> retry = RETRIES_TCP;
       nwk_schedule_oo_ack(_sckt);
 
     } else if (rel_sequence.d == _sckt -> rx_oo_end) {
       // Copy to end of OO data in RX buffer
 
       if (data_size + _sckt -> rx_oo_end > _sckt -> rx_size)
         data_size = _sckt -> rx_size - _sckt -> rx_oo_end;
       if (data_size) {
 
         lcopy(ETH_RX_BUFFER + 16 + data_ofs, _sckt -> rx + _sckt -> rx_oo_end, data_size);
 
         _sckt -> rx_oo_end += data_size;
 
         #ifdef DEBUG_TCP_REASSEMBLY
         snprintf(dbg_msg, 80, "   oo appending %d bytes: rel=%ld, oo_start=%ld, oo_end=%ld",
           data_size,
           rel_sequence.d, _sckt -> rx_oo_start, _sckt -> rx_oo_end);
         debug_msg(dbg_msg);
         #endif
       }
     } else if (((rel_sequence.d + data_size) >= _sckt -> rx_oo_start) &&
       (rel_sequence.d + data_size < _sckt -> rx_oo_end)) {
       // Copy to start of OO data in RX buffer
       if (data_size) {
         lcopy(ETH_RX_BUFFER + 16 + data_ofs, _sckt -> rx + rel_sequence.d, data_size);
 
         _sckt -> rx_oo_start = rel_sequence.d;
 
         #ifdef DEBUG_TCP_REASSEMBLY
         snprintf(dbg_msg, 80, "   Prepending %d bytes to oo_start. oo_start=%ld, oo_end=%ld",
           data_size,
           _sckt -> rx_oo_start, _sckt -> rx_oo_end);
         debug_msg(dbg_msg);
         #endif
       }
     } else if ((rel_sequence.d + data_size) < _sckt -> rx_size && !_sckt -> rx_oo_start) {
       // It belongs in the window, but not at the start, so put in RX OO buffer
       if (data_size) {
         lcopy(ETH_RX_BUFFER + 16 + data_ofs, _sckt -> rx + rel_sequence.d, data_size);
 
         _sckt -> rx_oo_start = rel_sequence.d;
         _sckt -> rx_oo_end = rel_sequence.d + data_size;
 
         #ifdef DEBUG_TCP_REASSEMBLY
         snprintf(dbg_msg, 80, "   stashing %d bytes: oo_start=%ld, oo_end=%ld",
           data_size,
           _sckt -> rx_oo_start, _sckt -> rx_oo_end);
         debug_msg(dbg_msg);
         #endif
       }
     } else if (rel_sequence.d) {
       #ifdef DEBUG_TCP_REASSEMBLY
       snprintf(dbg_msg, 80, "   Dropping %d bytes, because i can't buffer them.",
         data_size);
       debug_msg(dbg_msg);
       snprintf(dbg_msg, 80, "   (oo_start=%ld, oo_end=%ld)",
         _sckt -> rx_oo_start, _sckt -> rx_oo_end);
       debug_msg(dbg_msg);
       #endif
       if (data_size) {
         nwk_schedule_oo_ack(_sckt);
         _sckt -> toSend = ACK;
         goto drop;
       }
     }
 
     //     while(!PEEK(0xD610)) continue; POKE(0xD610,0);
 
     // Merge received data and RX OO area, if possible
     if (_sckt -> rx_data && _sckt -> rx_data == _sckt -> rx_oo_start) {
       _sckt -> rx_data = _sckt -> rx_oo_end;
       _sckt -> rx_oo_end = 0;
       _sckt -> rx_oo_start = 0;
 
       #ifdef DEBUG_TCP_REASSEMBLY
       snprintf(dbg_msg, 80, "   set rx_data to %ld (c).", _sckt -> rx_data);
       debug_msg(dbg_msg);
       #endif
 
     }
 
     /*
      * Update stream sequence number.
      * 1. Add number of bytes seen.
      * 2. If it is the first data after the connection handshake, subtract one
      *    for the extra byte acked during the handshake
      */
     if (0)
       if ((_sckt -> remSeq.d == (1 + _sckt -> remSeqStart.d)) &&
         (_sckt -> rx_data > 0)
       ) _sckt -> remSeq.d--;
 
     _sckt -> remSeq.d += _sckt -> rx_data;
 
     // Deliver data to programme
     if (_sckt -> rx_data) {
       tcp_bytes('b');
       _sckt -> callback(WEEIP_EV_DATA);
       remove_rx_data(_sckt);
     }
 
     // And ACK every packet, because we don't have buffer space for multiple ones,
     // and its thus very easy for the sender to not know where we are upto, and for
     // everything to generally get very confused if we have encountered any out-of-order
     // packets.
     _sckt -> toSend = ACK;
 
   }

   //printf("↓ TCP flags=%d  state=%d → ", TCPH(flags), _sckt->state);  
 
   // XXX PGS moved this lower down, so that we can check any included data has the correct sequence
   // number, so that we can pass the data up, if required, so that data included in the RST
   // packet doesn't get lost (Boar's Head BBS does this, for example)
   if (TCPH(flags) & RST) {
     /*
      * RST flag received. Force disconnection.
      */
     _sckt -> state = _IDLE;
     if (!data_size) {
       // No data, so just disconnect
       ev = WEEIP_EV_DISCONNECT;
     } else {
       // Disconnect AND valid data
       ev = WEEIP_EV_DISCONNECT_WITH_DATA;
     }
     goto done;
   }
 
   // If FIN flag is set, then we also acknowledge all data so far,
   // plus the FIN flag.
   if (TCPH(flags) & FIN || _sckt -> state == _FIN_REC) {
 
     _sckt -> remSeq.b[3] = TCPH(n_seq.b[0]);
     _sckt -> remSeq.b[2] = TCPH(n_seq.b[1]);
     _sckt -> remSeq.b[1] = TCPH(n_seq.b[2]);
     _sckt -> remSeq.b[0] = TCPH(n_seq.b[3]);
 
     _sckt -> remSeq.d += data_size;
     _sckt -> remSeq.d++;
     _flags |= FIN;
     //      printf("FIN ACK = %ld\n",_sckt->remSeq.d-_sckt->remSeqStart.d);
   }
 
   /*
    * TCP state machine implementation.
    */
   switch (_sckt -> state) {
   case _LISTEN:
     if (_flags & SYN) {
       /*
        * Start incoming connection procedure.
        */
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: _listen state");
       #endif
       _sckt -> state = _SYN_REC;
       _sckt -> toSend = SYN | ACK;
     }
     break;
 
   case _SYN_SENT:
 
     if (_flags & (ACK | SYN)) {
       /*
        * Connection established.
        */
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: _syn_sent state with syn or ack");
       #endif
       _sckt -> state = _CONNECT;
       _sckt -> toSend = ACK;
 
       // Advance sequence # by one to ack the ack
       _sckt -> seq.d++;
 
       ev = WEEIP_EV_CONNECT;
       //printf("Saw SYN\n");
       break;
     }
 
     if (_flags & SYN) {
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: _syn_sent state with syn");
       #endif
       _sckt -> state = _SYN_REC;
       _sckt -> toSend = SYN | ACK;
     }
     break;
 
   case _SYN_REC:
     if (_flags & ACK) {
       /*
        * Connection established.
        */
       _sckt -> state = _CONNECT;
       ev = WEEIP_EV_CONNECT;
     }
     break;
 
   case _CONNECT:
   case _ACK_WAIT:
     if (_flags & FIN) {
       /*
        * Start remote disconnection procedure.
        */
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: _ack_wait state");
       #endif
       _sckt -> state = _FIN_REC;
       _sckt -> toSend = ACK | FIN;
       ev = WEEIP_EV_DISCONNECT; // TESTE
       break;
     }
 
     if ((_flags & ACK) && (_sckt -> state == _ACK_WAIT)) {
       /*
        * The peer acknowledged the previously sent data.
        */
       _sckt -> state = _CONNECT;
     }
 
     if (data_size) {
       /*
        * Data received.
        */
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: data received");
       #endif
       _sckt -> toSend = ACK;
       ev = WEEIP_EV_DATA;
     }
     break;
 
   case _FIN_SENT:
 
     if (_flags & (FIN | ACK)) {
       /*
        * Disconnection done.
        */
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: _fin_sent state with fin or ack");
       #endif
       _sckt -> state = _IDLE;
       _sckt -> toSend = ACK;
       ev = WEEIP_EV_DISCONNECT;
       // Allow the final state to be selected based on ACK and FIN flag state.
       //            break;
     }
 
     if (_flags & ACK) {
       _sckt -> state = _FIN_ACK_REC;
     }
 
     if (_flags & FIN) {
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: _fin_ack_rec state with fin");
       #endif
       _sckt -> state = _FIN_REC;
       _sckt -> toSend = ACK;
       break;
     }
 
     break;
 
   case _FIN_REC:
     if (_flags & ACK) {
       /*
        * Disconnection done.
        */
       _sckt -> state = _IDLE;
       ev = WEEIP_EV_DISCONNECT;
     }
     break;
 
   case _FIN_ACK_REC:
     if (_flags & FIN) {
       /*
        * Disconnection done.
        */
       #ifdef DEBUG_ACK
       debug_msg("asserting ack: _fin_ack_rec state with fin");
       #endif
       _sckt -> state = _FIN_REC;
       _sckt -> toSend = ACK;
       ev = WEEIP_EV_DISCONNECT;
     }
     break;
 
   default:
     break;
   }
   
   done:
   
   //printf("toSend=%02x  newState=%d\r", _sckt->toSend, _sckt->state);

     /*
      * Verify if there are messages to send.
      * Add nwk_upstream() to send messages.
      */
     if (_sckt -> toSend) {
       _sckt -> retry = RETRIES_TCP;
       #ifdef INSTANT_ACK
       nwk_upstream(0);
       #endif
       #ifdef DEBUG_ACK
       debug_msg("scheduling nwk_upstream 0 0");
       #endif
       task_cancel(nwk_upstream);
       task_add(nwk_upstream, 0, 0, "upstream");
     }
 
   /*
    * Verify event processing.
    * Add socket management task.
    */
   if (ev != WEEIP_EV_NONE) {
      //printf("\rev=%d ", ev);
      byte_t call_ev = ev;
     //tcp_bytes('c');
     _sckt -> callback(call_ev);
     remove_rx_data(_sckt);
   }
 
   drop:
    //puts("\rdropped");
     return;
 }
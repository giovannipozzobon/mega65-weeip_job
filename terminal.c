#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "./weeip/include/task.h"
#include "./weeip/include/weeip.h"
#include "./weeip/include/eth.h"
#include "./weeip/include/arp.h"
#include "./weeip/include/dns.h"
#include "./weeip/include/dhcp.h"

#include "./mega65/include/memory.h"
#include "./mega65/include/random.h"

unsigned char last_frame_number=0;
unsigned long byte_log=0;

#define PORT_NUMBER 64128
#define HOST_NAME "rapidfire.hopto.org"
#define FIXED_DESTINATION_IP
#define USE_DHCP 1
#define ETH_FRAMECOUNT 0xD7FA

SOCKET *s;
byte_t rxbuf[20];
byte_t txbuf[1] = { 0 };
//byte_t *buf = (byte_t *)0x58F00;

/* Function that is used as a call-back on socket events */
byte_t com_callback (byte_t p)
{
  unsigned int i;
  unsigned char *rx=(unsigned char *)s->rx;

  socket_select(s);

//printf("\rsocket event: %d", p);

  switch(p) {
    case WEEIP_EV_CONNECT:
      puts("\rconnected!\r");
      // Send telnet GO AHEAD command
      //socket_send((unsigned char *)"\0377\0371",2);
      break;
    case WEEIP_EV_DATA:
    case WEEIP_EV_DISCONNECT_WITH_DATA:
      // Print what comes from the server
      for(i=0;i<s->rx_data;i++) {
        lpoke(0x40000+byte_log,rx[i]);
        byte_log++;
        //	  if ((rx[i]>=0x20)&&(rx[i]<0x7e)
        //	      ||(rx[i]==' ')||(rx[i]=='\r')||(rx[i]=='\n'))
        printf("%c",rx[i]);
        //	  else
        //	    printf("[$%02x]",rx[i]);
      }
      
      lpoke(0x12000,(byte_log>>0)&0xff);
      lpoke(0x12001,(byte_log>>8)&0xff);
      lpoke(0x12002,(byte_log>>16)&0xff);
      lpoke(0x12003,(byte_log>>24)&0xff);

      // Fall through if its a disconnect with data
      if (p==WEEIP_EV_DATA) break;

    // FALL THROUGH
    case WEEIP_EV_DISCONNECT:
      socket_release(s);
      printf("%c%c\r\rDISCONNECTED",5,12);
      break;
  }
  
  return 0;
}

void main(void)
{
  IPV4 remote_host;
  EUI48 mac;
  uint16_t port_number=PORT_NUMBER;
  char *hostname=HOST_NAME; 
  unsigned char i;
  
  mega65_io_enable();
  srand(random32(0));

  POKE(0xD020,0);
  POKE(0xD021,0);
  
  printf("%c%c",0x05,0x93);

  // Clear $D610 key buffer
  while(PEEK(0xD610)) POKE(0xD610,0);
  
  // Fix invalid MAC address multicast bit
  POKE(0xD6E9,PEEK(0xD6E9)&0xFE);
  // Mark MAC address as locally allocated
  POKE(0xD6E9,PEEK(0xD6E9)|0x02);
  
  // Get MAC address from ethernet controller
  for(i=0;i<6;i++)
    mac_local.b[i] = PEEK(0xD6E9+i);
  
  printf("My MAC address is %02x:%02x:%02x:%02x:%02x:%02x\r",
	  mac_local.b[0],mac_local.b[1],mac_local.b[2],
	  mac_local.b[3],mac_local.b[4],mac_local.b[5]);
  
  // Setup WeeIP
  printf("Resetting ethernet controller\r");
  weeip_init();
  task_cancel(eth_task);
  task_add(eth_task, 0, 0,"eth");
  
  // Clear buffer of received data we maintain for debugging
  lfill(0x12000,0,4);
  lfill(0x40000,0,32768);
  lfill(0x48000,0,32768);
  lfill(0x50000,0,32768);
  lfill(0x58000,0,32768);
  
#ifdef USE_DHCP
  // Do DHCP auto-configuration
  printf("Configuring network via DHCP\r");
  dhcp_autoconfig();
  while(!dhcp_configured) {
    task_periodic();
  }
#else
  ip_local.b[0]=192;
  ip_local.b[1]=168;
  ip_local.b[2]=1;
  ip_local.b[3]=165;
#endif
 
  ip_dnsserver = ip_gate;
  printf("My IP is %d.%d.%d.%d\r", ip_local.b[0],ip_local.b[1],ip_local.b[2],ip_local.b[3]);
    
  if (!dns_hostname_to_ip(hostname,&remote_host)) {
    printf("Could not resolve hostname '%s'\r",hostname);
    return;
  } 

  printf("Host '%s' resolves to %d.%d.%d.%d\r", hostname,remote_host.b[0],remote_host.b[1],remote_host.b[2],remote_host.b[3]);
  
  remote_host.b[0] = 192;
  remote_host.b[1] = 168;
  remote_host.b[2] = 1;
  remote_host.b[3] = 1;

  //printf("Host '%s' resolves to %d.%d.%d.%d\r", hostname,remote_host.b[0],remote_host.b[1],remote_host.b[2],remote_host.b[3]);

  EUI48 tmp_mac;
  arp_query(&remote_host);
  uint16_t t = 500;                        // 500 ms-ish
  while (!query_cache(&remote_host, &tmp_mac) && t--) {
    task_periodic();
  }

  if (!t) printf("ARP FOR %u.%u.%u.%u FAILED – off-subnet?\r",
    remote_host.b[0], remote_host.b[1],
    remote_host.b[2], remote_host.b[3]);

  s = socket_create(SOCKET_TCP); 

  if(s != NULL) {
    socket_select(s);
    socket_set_callback(com_callback);
    socket_set_rx_buffer((uint32_t)rxbuf, sizeof(rxbuf));
  }
  else {
    puts("\rsocket not created.");
    return;
  }
    
  socket_connect(&remote_host,port_number);
  task_periodic();

  while(1) 
  { 
    //task_periodic();
    
    // only call it periodically
    uint8_t fc = PEEK(ETH_FRAMECOUNT);
    if (fc != last_frame_number) {
        last_frame_number = fc;
        task_periodic();                  // ← runs eth_task() right away
    }

    if(PEEK(0xD610))
    {
      uint8_t key = PEEK(0xD610);
      
      if(key != 0x00 && key != 0xff) {
        
        POKE(0xD610, 0);

        txbuf[0] = key;
        printf("%c",key);

        socket_select(s);
        while (!socket_send(txbuf, sizeof(txbuf)))   /* wait until there’s room */
          task_periodic();           /* let ACK for previous byte arrive */
      }
    }
  }
}

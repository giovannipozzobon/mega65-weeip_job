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

#define PORT_NUMBER           64128
#define M65_KEYBOARD          0xD610
#define FIXED_DESTINATION_IP
#define USE_DHCP              1
#define ETH_FRAMECOUNT        0xD7FA

SOCKET *s;
byte_t rxbuf[20];
byte_t txbuf[1] = { 0 };
bool_t isconnected = FALSE;								  

// Prototypes
void term_init();
void term_network_init();
byte_t term_get_host(char *buf, size_t maxlen);
byte_t term_get_port(uint16_t *out_port);
byte_t term_event_callback (byte_t p);

void main(void)
{
  IPV4 remote_host;
  EUI48 mac;
  uint16_t port_number=PORT_NUMBER;
  char hostname[81]; 

  while(1) {

    term_init();
    term_network_init();

    bool_t valid = term_get_host(hostname, 80);
    valid = valid & term_get_port(&port_number);

    if (valid == TRUE) {

      if (!dns_hostname_to_ip(hostname,&remote_host)) {
        printf("\rcould not resolve hostname '%s'",hostname);
        getchar();
      }
      else {
        printf("\r\rconnecting to: %s:%u (%d.%d.%d.%d)...", hostname, port_number, 
          remote_host.b[0],remote_host.b[1],remote_host.b[2],remote_host.b[3]);

        EUI48 tmp_mac;
        arp_query(&remote_host);
        uint16_t t = 500;                        // 500 ms-ish
        while (!query_cache(&remote_host, &tmp_mac) && t--) {
          task_periodic();
        }
         
        s = socket_create(SOCKET_TCP); 
        socket_select(s);
        socket_set_callback(term_event_callback);
        socket_set_rx_buffer((uint32_t)rxbuf, sizeof(rxbuf));
        socket_connect(&remote_host,port_number);
        task_periodic();
      
        // assumption, but needed to allow time for actual connection
        // attempt to connect should timeout if not (?)
        isconnected = TRUE;

        do { 
          task_periodic();
          
          // only call it periodically
          uint8_t fc = PEEK(ETH_FRAMECOUNT);
          if (fc != last_frame_number) {
              last_frame_number = fc;
              //task_periodic();                            // runs eth_task() right away
          }
      
          if(PEEK(M65_KEYBOARD))
          {
            uint8_t key = PEEK(M65_KEYBOARD);
            
            if(key != 0x00 && key != 0xff) {
              
              POKE(M65_KEYBOARD, 0);
      
              txbuf[0] = key;
              //printf("%c",key);
      
              socket_select(s);
              while (!socket_send(txbuf, sizeof(txbuf)))  // wait until there’s room
                task_periodic();                          // let ACK for previous byte arrive
            }
          }

        } while (isconnected == TRUE);

      }
    }
  }
}

void term_init() {

  mega65_io_enable();
  srand(random32(0));

  POKE(0xD020,0);
  POKE(0xD021,0);
  
  printf("%c%c%c%cmega65 ethernet terminal                                                       %c\r\r",0x05,0x93,0x0e,0x12,0x92);

  // Clear $D610 key buffer
  while(PEEK(0xD610)) POKE(0xD610,0);

  // Fix invalid MAC address multicast bit
  POKE(0xD6E9,PEEK(0xD6E9)&0xFE);
  // Mark MAC address as locally allocated
  POKE(0xD6E9,PEEK(0xD6E9)|0x02);

  // Get MAC address from ethernet controller
  for(uint8_t i=0;i<6;i++)
    mac_local.b[i] = PEEK(0xD6E9+i);
  
  printf("mac address is %02x:%02x:%02x:%02x:%02x:%02x\r",
    mac_local.b[0],mac_local.b[1],mac_local.b[2],
    mac_local.b[3],mac_local.b[4],mac_local.b[5]);

}

void term_network_init() {
 
  // Setup WeeIP
  printf("resetting ethernet controller\r");
  weeip_init();
  task_cancel(eth_task);
  task_add(eth_task, 0, 0,"eth");
   
  #ifdef USE_DHCP
    // Do DHCP auto-configuration
    printf("configuring network via dhcp\r");
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

}

byte_t term_event_callback (byte_t b)
{
  unsigned int i;
  unsigned char *rx=(unsigned char *)s->rx;

  socket_select(s);

  //printf("\rsocket event: %d", p);

  switch(b) {
    case WEEIP_EV_CONNECT:
      puts("\r * connected\r");
      //socket_send((unsigned char *)"\0377\0371",2);  // Send telnet GO AHEAD command
      break;
    case WEEIP_EV_DATA:
    case WEEIP_EV_DISCONNECT_WITH_DATA:
      // Print what comes from the server
      for(i=0;i<s->rx_data;i++) {
        //lpoke(0x40000+byte_log,rx[i]);
        //byte_log++;
        //	  if ((rx[i]>=0x20)&&(rx[i]<0x7e)
        //	      ||(rx[i]==' ')||(rx[i]=='\r')||(rx[i]=='\n'))
        printf("%c",rx[i]);
        //	  else
        //	    printf("[$%02x]",rx[i]);
      }
      
      //lpoke(0x12000,(byte_log>>0)&0xff);
      //lpoke(0x12001,(byte_log>>8)&0xff);
      //lpoke(0x12002,(byte_log>>16)&0xff);
      //lpoke(0x12003,(byte_log>>24)&0xff);

      // Fall through if its a disconnect with data
      if (b==WEEIP_EV_DATA) break;

    // FALL THROUGH
    case WEEIP_EV_DISCONNECT:
      isconnected = FALSE;
      socket_release(s);
      printf("\r%c%c%c * disconnected <any key> ", 0x0e, 0x05, 0x92);
      getchar();
      break;
  }
  
  return 0;
}

byte_t term_get_host(char *buf, size_t maxlen)
{
    printf("\r - enter remote hostname: ");

    /* fgets reads at most maxlen-1 bytes plus the '\0' */
    if (!fgets(buf, (int)maxlen, stdin))
        return FALSE;           /* EOF or error */

    /* strip trailing newline if present */
    size_t len = strlen(buf);
    if (len && buf[len-1] == '\n')
        buf[len-1] = '\0';

    return TRUE;
}

byte_t term_get_port(uint16_t *out_val)
{
    uint16_t acc = 0;
    uint8_t c, got_digit = 0;

    puts("\r - enter remote port:");

    for (;;) {
        c = getchar();

        if (c == '\n' || c == '\r') { 
          putchar(0x0d); break;
        }

        if (c >= '0' && c <= '9') {
            got_digit = 1;
            acc = acc * 10 + (c - '0');
        }
        else {
            while (c != '\n' && c != '\r' && c != 0)
              c = getchar();
            return term_get_port(out_val);
        }
    }

    if (!got_digit)
        return FALSE;

    *out_val = acc;
    return TRUE;
}
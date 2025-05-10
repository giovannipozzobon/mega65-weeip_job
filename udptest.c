// mega65_udp_echo.c

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "./mega65/include/memory.h"    // for PEEK/POKE, mega65_io_enable()
#include "./mega65/include/random.h"    // for random32()

#include "./weeip/include/task.h"       // task_add(), task_periodic()
#include "./weeip/include/eth.h"        // eth_init(), eth_task
#include "./weeip/include/arp.h"        // arp_init()
#include "./weeip/include/weeip.h"      // ip_local, ip_mask, ip_gate


#define LOCAL_PORT 5005
#define BUF_SIZE   512

static SOCKET *udp_socket;
static uint8_t  buf[BUF_SIZE];

/// Called on socket events.  We only care about DATA→echo.
static byte_t udp_callback(byte_t ev) {

    socket_select(udp_socket);

    //printf("udp_cb called: ev=%u, rx_data=%lu\n", ev, udp_socket->rx_data);

    /*       printf("Defined constants: DATA=%u, SENT=%u; got ev=%u\n",
            (unsigned)WEEIP_EV_DATA,
            (unsigned)WEEIP_EV_DATA_SENT,
            (unsigned)ev);*/

    switch(ev) {
      case WEEIP_EV_DATA:
      case WEEIP_EV_DISCONNECT_WITH_DATA: {
        // Got real data → do ARP check
        EUI48 macbuf;
        if (!query_cache(&udp_socket->remIP, &macbuf)) {
          // We don’t know their MAC yet → send ARP request
          arp_query(&udp_socket->remIP);
          return 0;
        }

        // Now we have a MAC → dump and echo
        for (uint16_t i = 0; i < udp_socket->rx_data; i++) {
          uint8_t b = ((uint8_t*)udp_socket->rx)[i];
          if (b >= 32 && b < 127) putchar(b);
          else printf("[0x%02x]", b);
        }
        putchar('\n');

        // Echo it back
        socket_send((uint8_t*)udp_socket->rx, udp_socket->rx_data);
        break;
      }
      case WEEIP_EV_DATA_SENT:
        // Confirmation that socket_send() queued the packet
        //printf("→ queued echo (DATA_SENT)\n");
        break;
      default:
        printf("unhandled ev=%u\r", ev);
        break;
    }
    return 0;
}

void main(void) {
    // --- 1) Basic MEGA65 setup ---
    mega65_io_enable();
    srand(random32(0));

    // 2) Static IP (change to suit your LAN)
    ip_local.b[0] = 192;
    ip_local.b[1] = 168;
    ip_local.b[2] = 1;
    ip_local.b[3] = 142;            // Mega65 is 192.168.1.42

    ip_mask.b[0] = 255;
    ip_mask.b[1] = 255;
    ip_mask.b[2] = 255;
    ip_mask.b[3] = 0;              // /24

    ip_gate.b[0] = 192;
    ip_gate.b[1] = 168;
    ip_gate.b[2] = 1;
    ip_gate.b[3] = 1;              // your router

    // --- 3) Initialize network stack ---
    weeip_init();                  // sets up TCP tick
    eth_init();                    // reset 45E100
    arp_init();                    // clear ARP cache

    // Schedule the ethernet task
    task_cancel(eth_task);
    task_add(eth_task, 0, 0, "eth");

    printf("Mega65 UDP Echo @ %d.%d.%d.%d:%d\r",
        ip_local.b[0], ip_local.b[1], ip_local.b[2], ip_local.b[3],
        LOCAL_PORT);

    // --- 4) Create & bind UDP socket ---
    udp_socket = socket_create(SOCKET_UDP);
    socket_select(udp_socket);
    socket_set_rx_buffer((uint32_t)buf, BUF_SIZE);
    socket_set_callback(udp_callback);
    socket_listen(LOCAL_PORT);

    // --- 5) Main loop: drive the scheduler ---
    while (1) {
        task_periodic();
    }
}

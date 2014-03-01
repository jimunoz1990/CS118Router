/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;
    
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    
    
    
} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method: void sendARPRequest(struct sr_instance *sr, struct sr_arpreq *req)
 * Scope: Global
 *
 * This method is called to create an Ethernet frame to send an ARP request.
 *---------------------------------------------------------------------*/

void sendARPRequest(struct sr_instance *sr,
                    struct sr_arpreq *req)
{
    // Create request
    uint8_t *packet = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    
    // Fill out Ethernet header
    struct sr_if *interface = sr_get_interface(sr, req->packets->iface);
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
    memset(ethernet_header->ether_dhost, 255, ETHER_ADDR_LEN); // Sender host MAC address
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN); // Target host MAC address
    ethernet_header->ether_type = htons(0x806);  // Ethernet type
    
    // Fill out ARP header
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    arp_header->ar_hrd = htons(0x1);        // Hardware length
    arp_header->ar_pro = htons(0x800);      // Protocol length
    arp_header->ar_hln = ETHER_ADDR_LEN;    // # bytes in MAC address
    arp_header->ar_pln = sizeof(uint32_t);  // # bytes in IP address
    arp_header->ar_op = htons(0x1);         // Operation
    memcpy(arp_header->ar_sha, , ETHER_ADDR_LEN); // Sender hardware address
    arp_header->ar_sip = interface->ip;     // Sender IP address
    memset(arp_header->ar_tha, 255, ETHER_ADDR_LEN); // Target hardware address, 255.255.255.255.255.255
    arp_header->ar_tip = req->ip;           // Target IP address
    
    // Send request
    sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), req->packets->iface);
    free(packet);
}/* end sendARPRequest */

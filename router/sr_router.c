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
#define DEBUG 1
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
    if (len < sizeof(sr_ethernet_hdr_t))
    {
        printf("Error: length of incoming packet does not meet minimum ethernet frame size.");
        return;
    }
    uint16_t packet_ether_type = ntohs(((sr_ethernet_hdr_t *)packet)->ether_type);
    printf("*** -> Received packet of length %d  and of type: %d\n", len, packet_ether_type);
    if (DEBUG) printAllHeaders(packet, len);
    if (packet_ether_type == ETHERTYPE_IP)
    {
        if (DEBUG) printf("Received an IP packet!\n");
        sr_handle_ip_packet(sr, packet, len, interface);
    }
    else if (packet_ether_type == ETHERTYPE_ARP)
    {
        if (DEBUG) printf("Received an ARP packet!\n");
        sr_handle_arp_packet(sr, packet, len, interface);

    }
}
/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet(struct sr_instance* sr, 
        uint8_ t * ip_packet ,
        unsigned int len,
        char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives an ip packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.  This function performs sanity checks to make sure the
 * ip packet received is valid, and if so it will either 
 * 1. forward it to the next router if the ip is not destined for one of our interfaces.
 * 2. send the packet to an interface in our interface list.
 *---------------------------------------------------------------------*/

void sr_handle_ip_packet(struct sr_instance* sr, 
        uint8_t * ip_packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    if (sanity_check_ip(ip_packet,len) == -1) return; //makes sure ip format is correct
    struct sr_if * interface_list = sr->if_list; 
    sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(ip_packet + sizeof(sr_ethernet_hdr_t));
    while (interface_list != NULL) //see if incoming ip packet matches one of our interfaces
    {
        if (interface_list->ip == ip_header->ip_dst) //in our list of interfaces
        {
            break;
        }
        interface_list = interface_list->next;
    }

    if (interface_list != NULL) // matches one of our interfaces
    {
        if (ip_header->ip_p == IPPROTO_ICMP) // if its an ICMP echo send a ICMP reply
        {
            sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t *)((uint8_t *)ip_header + 
                sizeof(sr_ip_hdr_t)); //find icmp header by offseting by ip header size
            uint16_t icmp_checksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0; //to calculate correct checksum
            
            if (icmp_checksum != cksum(icmp_header,len-sizeof(sr_icmp_hdr_t))) //doesn't pass checksum
            {
                printf("Error: ICMP checksum failed.");
                return;
            }
            if (icmp_header->icmp_type == IPPROTO_ICMP_ECHO_REQUEST)
            {
                IcmpMessage(sr, ip_packet, IPPROTO_ICMP_ECHO_REPLY, IPPROTO_ICMP_DEFAULT_CODE); //send icmp echo reply if we receive a request
            }

        }
        else if (ip_header->ip_p == IPPROTO_TCP || 
                ip_header->ip_p == IPPROTO_UDP)
        {
            IcmpMessage(sr, ip_packet, IPPROTO_ICMP_DEST_UNREACHABLE, IPPROTO_ICMP_PORT_UNREACHABLE); //send unreachable message if receive a udp or tcp request
        }  
    }
    else // the ip dest is not in our list of interfaces
    {
       //TBD struct * sr_rt longest_prefix_match = find_longest_prefix();

        //TBD use routing table to see where to fwd to
    }
   

}
/*---------------------------------------------------------------------
 * Method: int sanity_check_ip(uint8_t * ip_packet,len)
 * Scope:  Global
 *
 * This method performs 3 sanity checks to make sure we have a valid IP Packet
 * 1) It checks that the packet length meets the minimum length requirement
 * 2) It checks whether the TTL value is valid.
 * 3) It recomputes the checksum of the sent data and compares it with the sent 
 * checksum in the IP header field.
 *---------------------------------------------------------------------*/
int sanity_check_ip(uint8_t * ip_packet,unsigned int len)
{
    if (sizeof(sr_ip_hdr_t) > len)
   {
    printf("Error: ip header size does not meet minimum length requirement. \n");
    return -1;
   }

   sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)( ip_packet + sizeof(sr_ethernet_hdr_t));
   if (ip_header->ip_ttl <= 1)
   {
    printf("Error: ip TTL <=1 for packet.\n");
    //need logic here for ICMP TBD when we do ICMP stuff
    return -1 ;
   }
   uint16_t sent_check_sum = ip_header->ip_sum;
   ip_header->ip_sum = 0x0000;
   uint16_t computed_check_sum = cksum(ip_header,sizeof(sr_ip_hdr_t));
   if (DEBUG) printf("Sent check sum: %d, Computed check sum: %d",sent_check_sum, computed_check_sum);
   if (sent_check_sum != computed_check_sum) 
   {
    printf("Error: Checksum: %d,  does not match computed checksum: %d.",sent_check_sum,computed_check_sum);
    return -1;
   }
   return 0;
}
void sr_handle_arp_packet(struct sr_instance* sr, 
        uint8_t * arp_packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
   //placeholder for handling arp packets
}


/* end sr_ForwardPacket */


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
    memcpy(arp_header->ar_sha,interface->addr , ETHER_ADDR_LEN); // Sender hardware address
    arp_header->ar_sip = interface->ip;     // Sender IP address
    memset(arp_header->ar_tha, 255, ETHER_ADDR_LEN); // Target hardware address, 255.255.255.255.255.255
    arp_header->ar_tip = req->ip;           // Target IP address
    
    // Send request
    sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), req->packets->iface);
    free(packet);
}/* end sendARPRequest */

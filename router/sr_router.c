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
#include <stdlib.h>
#include <string.h>

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
    if (DEBUG) printf ("length of packet: %u\n",len);
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
 *
 *                         ICMP FUNCTIONS
 *
 *---------------------------------------------------------------------*/

/* Fills Ip header, specifically used by sendIcmpMessage
 */
void fillIpHeader(sr_ip_hdr_t *ipHdr, sr_ip_hdr_t *oldIpHdr, uint32_t newPktLen, uint32_t newDest, struct sr_if *interface, uint8_t icmp_type, uint8_t icmp_code)
{
  ipHdr->ip_hl = oldIpHdr->ip_hl;
  ipHdr->ip_v = oldIpHdr->ip_v;
  ipHdr->ip_tos = oldIpHdr->ip_tos;
  ipHdr->ip_len = htons(newPktLen - sizeof(sr_ethernet_hdr_t));
  ipHdr->ip_id = 0;
  ipHdr->ip_off = htons (IP_DF | 0);
  ipHdr->ip_ttl = INIT_TTL;
  ipHdr->ip_p = IPPROTO_ICMP;
  ipHdr->ip_dst = newDest;
  if (icmp_type == IPPROTO_ICMP_ECHO_REPLY || (icmp_code == IPPROTO_ICMP_PORT_UNREACHABLE && icmp_type == IPPROTO_ICMP_DEST_UNREACHABLE))
  {  
    ipHdr->ip_src = oldIpHdr->ip_dst;
  } else {
    ipHdr->ip_src = interface->ip;  
  }
  ipHdr->ip_sum = 0;
  ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
}

void fillIcmpT3(sr_icmp_t3_hdr_t *icmpT3Hdr, uint8_t icmpType, uint8_t icmpCode, sr_ip_hdr_t *oldIpHdr)
{
  icmpT3Hdr->icmp_type = icmpType;
  icmpT3Hdr->icmp_code = icmpCode;
  icmpT3Hdr->icmp_sum = 0;
  icmpT3Hdr->unused = 0;
  icmpT3Hdr->next_mtu = 0;
  memcpy(icmpT3Hdr->data, oldIpHdr, ICMP_SIZE);
  icmpT3Hdr->icmp_sum = cksum(icmpT3Hdr, sizeof(sr_icmp_t3_hdr_t));
}

void fillIcmpEcho(sr_icmp_hdr_t *icmpHdr, uint32_t newPacketLen, uint8_t icmpType, uint8_t icmpCode, sr_ip_hdr_t *oldIpHdr)
{   
    icmpHdr->icmp_type = icmpType;
    icmpHdr->icmp_code = icmpCode;
    memcpy((uint8_t *)icmpHdr + sizeof(sr_icmp_hdr_t), (uint8_t *)oldIpHdr + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), newPacketLen - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
 
    icmpHdr->icmp_sum = 0;
    icmpHdr->icmp_sum = cksum(icmpHdr, newPacketLen - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
}

void IcmpMessage(struct sr_instance *sr, uint8_t *packet, uint8_t icmp_type, uint8_t icmp_code) {

	uint32_t newPktLen;
	sr_ip_hdr_t *oldIpHdr = (sr_ip_hdr_t *) packet;
	if (icmp_type == IPPROTO_ICMP_ECHO_REPLY)
	{
		newPktLen = sizeof(sr_ethernet_hdr_t) + ntohs(oldIpHdr -> ip_len);
	}
	else if (icmp_type == IPPROTO_ICMP_TIME_EXCEEDED || icmp_type == IPPROTO_ICMP_DEST_UNREACHABLE)
	{
		newPktLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	}
	//Obtain information from the next hop
	uint32_t newDest = oldIpHdr -> ip_src;
	// Perform longest prefix match
	struct sr_rt *rt = longest_prefix_match((struct sr_rt *) sr -> routing_table, newDest);
	if(!rt) //can't send -> drop because no match in the routing table
		return; 
	struct sr_if *interface = sr_get_interface(sr,rt->interface);
	
	uint8_t *newPkt = (uint8_t *)malloc(newPktLen);

	//Fill the header
	sr_ethernet_hdr_t *etherHdr = (sr_ethernet_hdr_t *)newPkt;
	memcpy ( etherHdr->ether_shost, interface ->addr, ETHER_ADDR_LEN);
	struct sr_arpentry *arpEntry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
	if(arpEntry ==NULL)
	{
		memset(etherHdr->ether_dhost, '\0', ETHER_ADDR_LEN);
	}
	else
	{
		memcpy(etherHdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
	}
	etherHdr->ether_type= htons(ETHERTYPE_IP);
	//Fill IP Header
	sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(newPkt + sizeof(sr_ethernet_hdr_t));
	fillIpHeader(ipHdr, oldIpHdr, newPktLen, newDest, interface, icmp_type, icmp_code);
  	// Fill Non-type3 ICMP 
	sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)((uint8_t *)ipHdr + sizeof(sr_ip_hdr_t));
  	// Fill Type3 ICMP
	sr_icmp_t3_hdr_t *icmpT3Hdr = (sr_icmp_t3_hdr_t *)icmpHdr;  

  if(icmp_type == IPPROTO_ICMP_ECHO_REPLY) {
    fillIcmpEcho(icmpHdr, newPktLen, icmp_type, icmp_code, oldIpHdr);    

  } else if (icmp_type == IPPROTO_ICMP_TIME_EXCEEDED || icmp_type == IPPROTO_ICMP_DEST_UNREACHABLE) {
    fillIcmpT3(icmpT3Hdr, icmp_type, icmp_code, oldIpHdr);
  }
  if (arpEntry) {
    sr_send_packet (sr, newPkt, newPktLen, rt->interface);
  } 
  else {
   // queue packet to get next hop MAC address
	struct sr_arpreq *arpRequest = sr_arpcache_queuereq (&sr->cache, rt->gw.s_addr, newPkt, newPktLen, rt->interface);
	// links rt and rf  
    handle_arpreq(sr, arpRequest);
  }
  free(newPkt);
}


/*---------------------------------------------------------------------
 *
 *                         IP FUNCTIONS
 *
 *---------------------------------------------------------------------*/

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
 * ip packet section of the ethernet frame it  received is valid, and if so it will either 
 * 1. forward it to the next router if the ip is not destined for one of our interfaces.
 * 2. send the packet to an interface in our interface list.
 * 3. Send proper ICMP messages to handle various cases
 * a) TTL <= 1 (unreachable)
 * b) TCP, UDP, (unreachable)
 * c) ICMP Echo Requests
 * d) Not found in routing table (unreachable)
 *---------------------------------------------------------------------*/

void sr_handle_ip_packet(struct sr_instance* sr, 
        uint8_t * ip_packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    if (DEBUG) printf("sr_handle_ip_packet len: %d\n",len);
    int sanity_check = sanity_check_ip(ip_packet,len);
    if (sanity_check == -1) return; //makes sure ip format is correct
     uint8_t * ethernet_data = (uint8_t *) (ip_packet + sizeof(sr_ethernet_hdr_t));
     if (sanity_check== -2) //TTL <=1, we need to send ICMP message
    {
        IcmpMessage(sr, ethernet_data, IPPROTO_ICMP_TIME_EXCEEDED, IPPROTO_ICMP_DEFAULT_CODE); 
    }
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
    else // the ip dest is not in our list of interfaces, check routing table
    {
       struct sr_rt *longest_p_m = longest_prefix_match(ip_header->ip_dst, sr->routing_table);
       if (longest_p_m == NULL)
       { //if we cant find it in routing table, dest is unreachable
            IcmpMessage(sr, ip_packet, IPPROTO_ICMP_DEST_UNREACHABLE, IPPROTO_ICMP_PORT_UNREACHABLE);
       }
       else //found in routing table
       {
            ip_header->ip_ttl--; //we checked for ip ttl stuff earlier so we dont have to here
            //TBD fill out stuff      
      
       }
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
 * returns -2 if TTL is expired so we can send the proper icmp_message
 * returns -1 if other errors were detected
 * returns 0 if passes sanity check
 *---------------------------------------------------------------------*/
int sanity_check_ip(uint8_t * ip_packet,unsigned int len)
{

    if (DEBUG) printf("sanity_check_ip len: %d\n",len);
   sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)( ip_packet + sizeof(sr_ethernet_hdr_t));
   if (DEBUG) printf("sanity_check_ip0 len: %d\n",len);
   if (ip_header->ip_ttl <= 1)
   {
    printf("Error: ip TTL <=1 for packet.\n");
    return -2 ;
   }
   if (DEBUG) printf("sanity_check_ip1 len: %d\n",len);
    if (sizeof(sr_ip_hdr_t) > len)
   {
    if (DEBUG) printf("sanity_check_ip2 len: %d\n",len);
    printf("Error: length of ip packet: %d does not meet minimum length of %d\n",
        len,sizeof(sr_ip_hdr_t));
    return -1;
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
/*---------------------------------------------------------------------
 * struct sr_rt * longest_prefix_match(uint32_t ip_dest, struct sr_rt * rt)
 * Scope:  Global
 *
 * Does a bitwise AND of the ip_destination and subnet mask
 * and tries to locate it in our current routing table based on
 * longest prefix matching.  Returns a the sr_table entry associated
 * with the ip destination, or if not found, returns NULL
 *---------------------------------------------------------------------*/
struct sr_rt* longest_prefix_match(uint32_t ip_dest, struct sr_rt * rt)
{
    struct sr_rt * current_entry = rt;
    struct sr_rt * longest_p_m = NULL; //initalize to null
    while (current_entry != NULL)
    {
        if ((current_entry->dest.s_addr & current_entry->mask.s_addr) ==
            (ip_dest & current_entry->mask.s_addr)) //bitwise and oper on the ip and subnet mask match table entry
        {

            if (longest_p_m == NULL)  // need to check null first or else statement will return seg fault
            {
                longest_p_m = current_entry;
            }
            else if (current_entry->mask.s_addr > longest_p_m->mask.s_addr)
            {
                longest_p_m = current_entry;
            }

        }
        current_entry = current_entry->next;
    }
    return longest_p_m;
}

/*---------------------------------------------------------------------
 *
 *                         ARP FUNCTIONS
 *
 *---------------------------------------------------------------------*/

/*---------------------------------------------------------------------
 * Method: void sr_handle_arp_packet(struct sr_instance* sr,
             uint8_t * arp_packet,
             unsigned int len,
             char* interface)
 * Scope: Global
 *
 * This method determines if ARP packet is request or reply and
 * processes accordingly.
 *---------------------------------------------------------------------*/


void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *arp_packet,
                          unsigned int len,
                          char *interface)
{
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_packet + sizeof(sr_ethernet_hdr_t));
    // If packet is a request
    if (ntohs(arp_hdr->ar_op) == ARP_REQUEST) {
        struct sr_if *interface_list = sr->if_list;
        while (interface_list != NULL)
        {
            if (interface_list->ip == arp_hdr->ar_tip)
            {
                break;
            }
            interface_list = interface_list->next;
        }
        
        if (interface_list) {
            // Make ARP reply
            uint8_t *arp_rep = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            
            // Fill out Ethernet header
            sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)arp_rep;
            memcpy(ethernet_header->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(ethernet_header->ether_shost, interface_list->addr, ETHER_ADDR_LEN);
            ethernet_header->ether_type = htons(ETHERTYPE_ARP);
            
            // Fill out ARP header
            sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(arp_rep + sizeof(sr_ethernet_hdr_t));
            arp_header->ar_hrd = htons(ARP_HRD_ETHER);      // Hardware length
            arp_header->ar_pro = arp_hdr->ar_pro;           // Protocol length
            arp_header->ar_hln = arp_hdr->ar_hln;           // # bytes in MAC address
            arp_header->ar_pln = arp_hdr->ar_pln;           // # bytes in IP address
            arp_header->ar_op = htons(ARP_REPLY);
            memcpy(arp_header->ar_sha, interface_list->addr, ETHER_ADDR_LEN);
            arp_header->ar_sip = arp_hdr->ar_tip;
            memcpy(arp_header->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            arp_header->ar_tip = arp_hdr->ar_sip;
            
            // Send reply
            sr_send_packet(sr, arp_rep, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
            free(arp_rep);
        }
    }
    // If packet is a reply
    else if (ntohs(arp_hdr->ar_op) == ARP_REPLY) {
        // Insert into ARP cache
        struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        
        if (arp_req) {
            struct sr_packet *packets = arp_req->packets;
            // Send waiting packets
            while (packets != NULL) {
                sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)(packets->buf);
                memcpy(ethernet_header->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                sr_send_packet(sr, packets->buf, packets->len, packets->iface);
                packets = packets->next;
            }
            
            // Clean up
            sr_arpreq_destroy(&sr->cache, arp_req);
        }
    }
}


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
    ethernet_header->ether_type = htons(ETHERTYPE_ARP);  // Ethernet type
    
    // Fill out ARP header
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    arp_header->ar_hrd = htons(ARP_HRD_ETHER);      // Hardware length
    arp_header->ar_pro = htons(ARP_PRO_ETHER);       // Protocol length
    arp_header->ar_hln = ETHER_ADDR_LEN;            // # bytes in MAC address
    arp_header->ar_pln = sizeof(uint32_t);          // # bytes in IP address
    arp_header->ar_op = htons(ARP_REQUEST);         // Operation
    memcpy(arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN); // Sender hardware address
    arp_header->ar_sip = interface->ip;     // Sender IP address
    memset(arp_header->ar_tha, 255, ETHER_ADDR_LEN); // Target hardware address, 255.255.255.255.255.255
    arp_header->ar_tip = req->ip;           // Target IP address
    
    // Send request
    sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), req->packets->iface);
    free(packet);
}/* end sendARPRequest */

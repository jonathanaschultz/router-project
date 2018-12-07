UCLA CS118 Fall18 Project 1 (Simple Router)
====================================

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)
## Submission User Information

Name: Jonathan Schultz
UID: 104-941-879

## High-Level Implementation/Design

My design/logic can be divided into the various functions that I implemented:
handlePacket() (found in simple-router.cpp):
- Begins by performing a basic sanity check to make sure the interface is valid
- Gets the packet type and stores it
- Verifies that the hardware address stored in the packet matches either the interface or broadcast address
	- If it doesn't, drops the packet
- Checks the packet type to ensure that it's either ARP or IPv4
	- If neither, drops the packet
- The flow for handling an IP packet is as follows:
	- Pre-forwarding stage:
		- Sanity check to make sure the packet is of proper size, drops it if not
		- Uses the packet information to generate a pointer to the IP header stored in the packet
		- Sanity check to make sure the IP header is of proper size, drops it if not
		- Performs checksum on the header and compares it to the original one stored in the header, drops packet if it doesn't match
		- Loops over interfaces associated with the router to ensure that the packet isn't destined for the router, drops packet if so
		- Decrements TTL, verifies that TTL is still within range (drops packet if not), then recalculates and stores checksum in the header
	- Forwarding stage:
		- Calls longest-prefix algorithm to find the next hop's RoutingTableEntry based on the destination IP
		- Use the RoutingTableEntry to find and store the interface associated with that hop
		- Looks up ARP entry associated with that hop to see if an ARP entry exists in the cache
		- If one exists in the ARP cache:
			- Refer to the ethernet header already stored within the packet
			- Updates ethernet header's type to IP
			- Swaps the destination and source hosts stored in the ethernet header
			- Uses the given ARP entry's MAC address as the new destination host in the ethernet header
			- Sends packet to the appropriate interface
		- If one DOESN'T exist in the ARP cache:
			- Signal the ARP table to queue an ARP request with the information from the RoutingTableEntry, packet, and interface
			- Allocates the appropriate memory for an ethernet header and ARP header (to store the request information)
			- Uses the interface's address as the source host in the ethernet header
			- Uses the generic BroadcastEtherAddr as the destination host in the ethernet header
			- Sets the ethernet header's type to ARP
			- Fills in the appropriate basic details within the ARP request
			- Sets arp_sha to the hardware address associated with the hop's interface
			- Sets arp_sip to the IP address associated with the hop's interface
			- Sets arp_tha to the generic BroadcastEtherAddr
			- Sets arp_tip accordingly based on the RoutingTableEntry
			- Sends packet to the appropriate interface
- The flow for handling an ARP packet is as follows:
	- Sanity check to make sure the packet is of proper size, drops it if not
	- Uses the packet information to generate a pointer to the ARP header stored in the packet
	- Checks the packet type to ensure that it's either for an ARP request or reply, drops the packet if neither
	- If type is an ARP request:
		- Sanity check to make sure that the ARP IP and interface IP are equal, drops packet if not
		- Allocates the appropriate memory for an ethernet header and ARP header (to store the reply information)
		- Constructs an ethernet header with the type set to ARP, the interface's hardware address as the source host, the source hardware address stored in the existing ARP header as the destination host
		- Fills in the appropriate basic details within the ARP reply
		- Sets arp_sha to the hardware address associated with the interface
		- Sets arp_sip to the IP address associated with the interface
		- Sets arp_tha to the source hardware address stored in the existing ARP header
		- Sets arp_tip to the source IP address stored in the existing ARP header
		- Sends packet to the appropriate interface
	- If type is an ARP reply:
		- Allocates the appropriate memory to store the hardware address to insert into the ARP cache
		- Copies the source hardware address in the existing ARP header to this new memory
		- Insert the ARP entry into the cache
		- If we don't receive a valid reply from the ARP cache (ie error in queueing the packet), drop the packet
		- Otherwise:
			- Loop over the packets stored within the ARP request, and for each do the following
			- Set the destination host in the ethernet header to the hardware address stored in the buffer
			- Set the source host in the ethernet header to that of the interface associated with the packet
			- Decrement the time-to-live associated with the packet, recalculate checksum
			- Send the packet over the appropriate interface
			- Once all packets have been sent, remove the request from the ARP table
			
lookup(uint32_t) (found in routing-table.cpp):
- Assuming the list of entries in the routing table isn't empty:
	- Make a copy of the routing table
	- Sort through the routing table w/ a simple lambda function that sorts in mask order
	- Loop over all the entries, and for each one:
	- If (mask AND dest) is equal to (mask AND ip) [where IP is the parameter to the lookup function], we've found the entry we want based on longest-prefix, so return that entry
- Otherwise, throw a runtime error saying that the entry wasn't found

periodicCheckArpRequestsAndCacheEntries() (found in arp-cache.cpp):
- Begin by looping over all the ARP requests, and for each:
	- Dereference to get the location of the request itself
	- If the number of times the request has been sent is greater than or equal the maximum times a request should be sent:
		- Loop over all the packets in the request and erase them
		- Remove the pending ARP request
	- Otherwise:
		- Allocates the appropriate memory for an ethernet header and ARP header
		- Gets the name of the interface/the interface itself associated with the first packet in the header
		- Sets the type in the ethernet header to ARP
		- Sets the interface's hardware address as the source host, and the BroadcastEtherAddr as the destination host within the ethernet header
		- Fills in the appropriate basic details within the ARP request
		- Sets arp_sha to the hardware address associated with the interface
		- Sets arp_sip to the IP address associated with the interface
		- Sets arp_tha to the generic BroadcastEtherAddr
		- Sets arp_tip to the IP address stored in the request
		- Sends packet to the appropriate interface
		- Updates the timeSent in the request to the current time, increments the number of times sent
- Loop over all the entries in the cache, and for each:
	- If the cache is valid, iterate to the next entry
	- Otherwise, remove the entry from the cache
	
## Problems Encountered During Implementation

There were 3 main issues that I encountered throughout the project:

- First, there were a number of problems with byte order, due to the endianness difference that occurs on x86 systems when compared to network byte order - as such, some fields that I tried to parse/add to headers wound up being garbage until using the appropriate htons or ntohs functions.
- Second, directly referring to the contents of packets often caused issues as well, since the .data() function of a Buffer only returns a pointer to the data. In order to fix this issue, I used C++'s reinterpret_cast call (sometimes combined with const_cast depending on the context, otherwise the compiler would yell about CV-qualifiers) to properly access fields within headers/packets
- Finally, I ran into issues involving directly referring to the interface names directly from the packet information - I solved this by storing the interface name in a string first.
		

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).
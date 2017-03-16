# Multidrop

Multidrop is a set of multicast broadcasting debugging tools and monitoring daemons intended to be used as "drops", that 
is small devices plugged in multiple places in the network.

Multicast AV broadcasting easily falls prey to issues such as frame drops, buggy MLD/IGMP snooping implementations, 
configuration errors and loops causing degraded services.  In a larger network, one could use the multidrop daemons to 
monitor for localized outages, and the tools to debug a more specific issue.

## sapdump

`sapdump` dumps SAP announcements to the console, eg. to debug missing channels

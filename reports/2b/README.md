### WT1

The destination MAC address is fetched from routing table which is calculated by the DV algorithm. 

### WT2

I implemented a DV algorithm. 

The dv packet will serve as a heartbeat packet and as a distance vector carrier. 

```sql
[(ASCII String)DistVector:10byte][Sender Port MAC:6Byte][VectorDim:4ByteBigEndianInt]{[IP:4ByteBigEndianInt|HopCount:4ByteBigEndianInt]*VectorDim}
```

Server will broadcast this packet to all its port(like "veth-0") every 0.5 seconds.

The receiver will use this packet to update it's local state. 

When on server haven't heard from its neighbor for more than 5 seconds, it deletes all the route table entry that goes through that neighbor(nextHop = neighbor mac).

### CP3

![image-20211103160959815](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103160959815.png)

The exact meaning of each bits is clear in the wireshark panel.

One thing also worth to notice is that my program correctly calculated the checksum.

### CP4


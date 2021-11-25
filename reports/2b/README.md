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

One thing also worth to notice is that my program correctly calculated the checksum for IP header.

### CP4

![image-20211103164547619](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103164547619.png)

This picture shows the change of distance vector in ns1 when boot ns1, ns2, ns3, ns4 in a sequence.

![image-20211103165012757](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103165012757.png)

After I ended the ns2 process, ns1 recalculated its distance vector.

![image-20211103165116102](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103165116102.png)

When I reboot ns2, ns1 successfully updated its distance vector.

### CP5

Shut down ns5 will not make much difference, let's shut down ns3 instead(and add a link ns6->ns4 at the same time).

Here is the topology now. 

![image-20211103170735523](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103170735523.png)



One thing should be noticed that you can distinguish the result from the '*' on green line. 



This is the distance vector **before** shut down ns5.

![image-20211103171203493](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103171203493.png)

![image-20211103171221108](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103171221108.png)

![image-20211103171238808](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103171238808.png)

![image-20211103171257872](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103171257872.png)

![image-20211103171311437](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103171311437.png)

![image-20211103171323529](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103171323529.png)

This is the distance vector **after** shut down ns5.

![image-20211103173925393](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103173925393.png)

We can see that the distance from ns1 to ns4 change to 4.

![image-20211103174106340](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103174106340.png)

![image-20211103174123948](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103174123948.png)

![image-20211103174137690](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103174137690.png)

![image-20211103174149004](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103174149004.png)

One way to avoid this weird self loop packet is to use a special type of packet to broadcast that certain host is down.

### CP6

![image-20211103170316694](C:\Users\haozh\AppData\Roaming\Typora\typora-user-images\image-20211103170316694.png)

When querying route table, only the one with the longest prefix will be preserved. 


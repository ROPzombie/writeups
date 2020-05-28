### root-me.org
#### Network Ch3 - Raw Ethernet Frame

This challenge just gives you a raw hex dump of an Ethernet frame. Inside the frame the flag has to be found. The following represents the hex dump as supplied by the challenge.

```hex
00 05 73 a0 00 00 e0 69 95 d8 5a 13 86 dd 60 00
00 00 00 9b 06 40 26 07 53 00 00 60 2a bc 00 00
00 00 ba de c0 de 20 01 41 d0 00 02 42 33 00 00
00 00 00 00 00 04 96 74 00 50 bc ea 7d b8 00 c1
d7 03 80 18 00 e1 cf a0 00 00 01 01 08 0a 09 3e
69 b9 17 a1 7e d3 47 45 54 20 2f 20 48 54 54 50
2f 31 2e 31 0d 0a 41 75 74 68 6f 72 69 7a 61 74
69 6f 6e 3a 20 42 61 73 69 63 20 59 32 39 75 5a
6d 6b 36 5a 47 56 75 64 47 6c 68 62 41 3d 3d 0d
0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 49 6e 73
61 6e 65 42 72 6f 77 73 65 72 0d 0a 48 6f 73 74
3a 20 77 77 77 2e 6d 79 69 70 76 36 2e 6f 72 67
0d 0a 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d
0a 

```
There are several options: The fastest: Just decode the whole hex dump to a string. The last few bytes will get you nearly to the answer.
But I suggest a deeper dive. Therefore lets dissect the dump.

Hint: I know Ethernet has an preamble field, but this is not part of the packet. It starts right with the destination and source address.

We have 14 lines, the first 13 each 16 Bytes the last lines contains only one entry. We can transfer them to a .pcap file or work just on raw information from the dump.
If we analyse the frame we see that the fist 14 Bytes are the exactly the size of an Ethernet frame, therefore it should be the Ethernet frame header. Taking a deeper look at:

```hex
00 05 73 A0 00 00
```
These are the destination address and as this is on link layer we are talking about MAC addresses. Thus the MAC address is 00:05:73:a0:00:00 first three hex values are the vendor specific part: 00 05 73 that tells us it is a CISCO  device.

```hex
E0 69 95 D8 5A 13 86 DD
```
The above encodes the source address, likewise the destination address is a MAC address, that tells it is from PEGATRON CORPORATION (vendor part E06995).

The next two bytes declares the type field that will declare which protocol is run on the network layer. Thus 86 DD tells us it is an IPv6 packet! (Well they are really modernest guys at root-me ^^)

So as the IPv6 header is 40 Bytes long it starts from Bytes 12 onwards. The payload is 155 Bytes containing a TCP packet on the transport layer. Some features that can be extracted are the hops (TTL in IPv4, length of 8 Bit = 0-255) which is set to $64 = 2^6$ They encoded a nice source address: 2607:5300:60:2abc::bade:c0de.

Next on is the transport layer with the TCP packet. The header tells us the source port is hex 96 74 or 38516 (as outgoing ports are random above ephemeral ports) and as the number is below IANA suggestions ranging from 49152 to 65535 it can be assumed that this is Linux (32768 to 60999) or FreeBSD (1024 to 5000 as ephemeral ports) system.

The destination port is 80 (hex 00 50) so the standard web port. Which makes sense, otherwise we have to handle TLS crypto stuff for HTTPs. But we also know what is waiting on the application layer: HTTP. All other field flags for TCP are 0 (hex 80 18). We skip the rest of TCP stuff - if you are interested go ahead and analyse it.

Okay: This is the final part you have waited for -- HTTP
```hex
47 	45 	54 	20 	2F 	20 	48 	54 	54 	50
2F 	31 	2E 	31 	0D 	0A 	41 	75 	74 	68 	6F 	72 	69 	7A 	61 	74
69 	6F 	6E 	3A 	20 	42 	61 	73 	69 	63 	20 	59 	32 	39 	75 	5A
6D 	6B 	36 	5A 	47 	56 	75 	64 	47 	6C 	68 	62 	41 	3D 	3D 	0D
0A 	55 	73 	65 	72 	2D 	41 	67 	65 	6E 	74 	3A 	20 	49 	6E 	73
61 	6E 	65 	42 	72 	6F 	77 	73 	65 	72 	0D 	0A 	48 	6F 	73 	74
3A 	20 	77 	77 	77 	2E 	6D 	79 	69 	70 	76 	36 	2E 	6F 	72 	67
0D 	0A 	41 	63 	63 	65 	70 	74 	3A 	20 	2A 	2F 	2A 	0D 	0A 	0D
0A 	
```
This is the HTTP part of the message. A http get invocation. First 3 Bytes for the request get method, followed one Byte for the URI (2f), then the request version HTTP/1.1. 

Finally we have HTTP basic authorization:
```hex
41 	75 	74 	68 	6F 	72 	69 	7A 	61 	74
69 	6F 	6E 	3A 	20 	42 	61 	73 	69 	63 	20 	59 	32 	39 	75 	5A
6D 	6B 	36 	5A 	47 	56 	75 	64 	47 	6C 	68 	62 	41 	3D 	3D 	0D
0A
```
Which we can decode to ASCII string **Authorization: Basic HEREISSOMETHNG==\r\n** The two equal signs tells us that this is base64 decoded. Via shell you can decode this:
```bash
base64 -d FILENAME
#or
echo "BASECODE==" | base64 -d
```
So now we have our flag and can get the points.
Really nice challenge for beginners interested in networking. As you do analyse through the OSI model. It was fun to dig through this.

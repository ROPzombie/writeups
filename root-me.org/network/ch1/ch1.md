# Network Ch1 FTP - Authentication

Original challenge can be found at: <https://www.root-me.org/en/Challenges/Network/FTP-authentication>

This is an easy one: We get a pcap file, which can open in Wireshark.
![FTP Auth in Wireshark](ch1_ws.jpg)
First thing filter for FTP protocol to lessen the seen output. Second watch out for requests and responses that do so say something about login and password stuff. And there you go, boom! Just right there is the password. Piece of cake!
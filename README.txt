---------------------------------------------------------
Netronome INT Transit Device Demo
---------------------------------------------------------

--------------------
P4 Application
--------------------

The P4 application forwards only INT VXLAN GPE packets from vf2 (v0.2)
to vf0 (v0.0), from vf0 to vf1 (v0.1) and vf1 to vf2 again. Each hop through
the dataplane will insert INT instructions, most significantly:
* switch ID in slot 0
* ingress timestamp in slot 1
* egress timestamp in slot 2
All non INT packets will be dropped.

Files for the project are found in dataplane/p4src and dataplane/csrc; rules
can be found in dataplane/p4cfg.

To build the firmware enter dataplane/build and run 'make'. Be sure to set the
SDKDIR environment variable to the path of your NFP SDK toolchain directory.

Note: one could edit the rules in dataplane/p4cfg and change v0.2 to p0 to use the
physical port rather than the VF netdev. The VF netdev is used so this demo
can be run with only the Netronome NIC for convenience sake

Note: that the demo called for a non-compliant INT implementation.
Look out for the INT_TO_SPEC define which enables the "to-spec" behavior.

---------------------
Host ifbounce utility
---------------------
In host/ifbounce is a simple C program which uses raw sockets to read and write
back a packet on a given linux network interface.

One can introduce latency in this application using SIGUSR1/2. Refer to the
source code for more info.

In host/ifbounce run 'make' to build.

---------------------------------
Using the INT traffic dumper tool
---------------------------------

in host/traffic there is a tool decode_gpe_int.py
which can parse and dump gpe INT traffic
run it on an interface like tcpdump:
./decode_gpe_int.py vf0_0
or on a pcap file:
./decode_gpe_int.py gpe_int_3sets.pcap

-----------------------------------------------------
Running the Demo
-----------------------------------------------------

Make sure the NFP SDK P4 runtime server is running in NETDEV mode (the default).

Enter dataplane/build and run "./load.sh". This will load firmware and
rules.

run the traffic bounce utility on two terminals:
./host/ifbounce/ifbounce vf0_0
and
./host/ifbounce/ifbounce vf0_1
this will return whatever traffic arrives on vf0_0 and vf0_1 back on the same
port untouched.

on one terminal run:
./host/traffic/decode_gpe_int.py vf0_2
this will display the traffic into and out of the Netronome NIC.

on another terminal run to inject a packet:
tcpreplay -i vf0_2 host/traffic/gpe_bfoot.pcap

you should see the following output (note that your timestamp will be different):
packet #0
packet #1
    [0] switch_id | bos : 0x0 | switch_id : 0xcafe | 
    [0] ingress_ts | bos : 0x0 | value : 0x7661ee71 | 
    [0] egress_ts | bos : 0x0 | value : 0x7661fe71 | 
    [1] switch_id | bos : 0x0 | switch_id : 0xcafe | 
    [1] ingress_ts | bos : 0x0 | value : 0x7661ca93 | 
    [1] egress_ts | bos : 0x0 | value : 0x7661da93 | 
    [2] switch_id | bos : 0x0 | switch_id : 0xcafe | 
    [2] ingress_ts | bos : 0x0 | value : 0x7661a076 | 
    [2] egress_ts | bos : 0x1 | value : 0x0x7661ba93 | 

The first packet going into vf0_2 is a GPE INT packet with no intructions,
the second packet has instruction added for all three ingress stages.

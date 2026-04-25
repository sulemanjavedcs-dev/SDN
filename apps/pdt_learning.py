from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet, arp, ipv4, ipv6, tcp

from controller import CockpitApp
from ipaddress import IPv4Address, IPv4Network

ETHERTYPES = {2048: "IPv4", 2054: "ARP", 34525: "IPv6"}
L4PROTO = {1: "ICMP", 4: "IP-in-IP", 6: "TCP", 17: "UDP"}


## TODO 1: What's going on? Get an overview over the code and analyze the situation.
#    --> Try: H1 ping H2
#             H3 ping H4
#             pingall
#             iperf H1 H2
#
#             dpctl dump-flows -O OpenFlow13


class LearningSwitch(CockpitApp):
    ## Initialize SDN-App
    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.pkt_count = {}

    def debug_output(self, dp, pkt, in_port):
        eth = pkt.get_protocol(ethernet.ethernet)

        self.pkt_count[dp.id] += 1

        ## TODO 2: Enable some more logging?

    #        ## Info: Packet-in / Ethernet packet
    #        print(f"/// [Switch {dp.id}]: PACKET-IN (#{self.pkt_count[dp.id]}) on port: {in_port}")
    #        print(f"      SRC: {eth.src}, DST: {eth.dst} --> {ETHERTYPES[eth.ethertype]}")
    #
    #        ## Info: IP Packet
    #        if eth.ethertype == ether_types.ETH_TYPE_IP:
    #            ip_pkt = pkt.get_protocol(ipv4.ipv4)
    #            print(f"           {ip_pkt.src:17},      {ip_pkt.dst:17} --> {L4PROTO[ip_pkt.proto]}")
    #
    #            ## Info: TCP Packet
    #            if ip_pkt.proto == 6:
    #                tcp_pkt = pkt.get_protocol(tcp.tcp)
    #                print(f"      SRC-PORT: {tcp_pkt.src_port}, DST-PORT: {tcp_pkt.dst_port}, SEQ: {tcp_pkt.seq}, ACK: {tcp_pkt.ack}")
    #
    #        ## Info: ARP Packet
    #        if eth.ethertype == ether_types.ETH_TYPE_ARP:
    #            arp_pkt = pkt.get_protocol(arp.arp)
    #            print(f"  [ARP] SRC-MAC: {arp_pkt.src_mac}, SRC-IP: {arp_pkt.src_ip}; DST-MAC: {arp_pkt.dst_mac} DST-IP: {arp_pkt.dst_ip}")
    #
    #    # --> see https://osrg.github.io/ryu-book/en/html/packet_lib.html for more info

    ## When a new switch connects to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath

        ## init (per-data path) variables
        self.mac_to_port[dp.id] = {}
        self.pkt_count[dp.id] = 0

        ## Note: check example for syntax how-to.
        # self.example()

        ## some debug output
        print("")
        print("")
        print(f"/// Switch connected. ID: {dp.id}")

        ## default "all to controller" flow
        match = parser.OFPMatch()
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.program_flow(dp, match, action, priority=0)

        ## Directly connect port 1 and 2 with proactive flow rules
        match = parser.OFPMatch(in_port=1)
        action = [parser.OFPActionOutput(2)]
        self.program_flow(dp, match, action, priority=100)

        match = parser.OFPMatch(in_port=2)
        action = [parser.OFPActionOutput(1)]
        self.program_flow(dp, match, action, priority=100)

        ## --> see https://osrg.github.io/ryu-book/en/html/openflow_protocol.html for more match options,
        ##       e.g.: action = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

    ## When a new packet comes in at the controller -- "PACKET-IN"
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # all info is stored in the ev object, extract some relevant fields
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        data = msg.data
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # ignore LLDP Packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.debug_output(dp, pkt, in_port)

        ## TODO 3: Flood all packets (i.e., controller based hub).
        if False:
            print("  --> FLOOD PACKET")
            self.send_pkt(dp, data, port=ofproto.OFPP_FLOOD)
        else:
            print("  --> DROP PACKET")

        ## TODO 4: Controller based switch. Learn MAC-->Port
        ## TODO 5: Push flow rules into the SDN-switch

    ## Example code
    def example(self, dp):
        self.mac_to_port[dp.id]["00:00:00:00:00:01"] = 99

        try:
            port = self.mac_to_port[dp.id]["00:00:00:00:00:01"]
            print(f"port: {port}")

            port = self.mac_to_port[dp.id]["00:00:00:00:00:02"]
            print(f"port: {port}")

        except KeyError:
            print("no port found!")

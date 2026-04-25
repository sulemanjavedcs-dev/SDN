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


class SecureGateway(CockpitApp):
    # initialize SDN-App
    def __init__(self, *args, **kwargs):
        super(SecureGateway, self).__init__(*args, **kwargs)
        self.pkt_count = {}

    # you already know this function from the lab
    def debug_output(self, dp, pkt, in_port):
        eth = pkt.get_protocol(ethernet.ethernet)

        self.pkt_count[dp.id] += 1

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

    # when a new switch connects to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath

        self.pkt_count[dp.id] = 0

        # some debug output
        print("")
        print("")
        print(f"/// Switch connected. ID: {dp.id}")

        # default "all to controller" flow
        match = parser.OFPMatch()
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.program_flow(dp, match, action, priority=0)

        # flood ARP (this is just to get ping to work)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        action = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.program_flow(dp, match, action, priority=1)

        # set up some proactive flows
        self.flow_example(dp)
        # self.flow_example_groups(dp)

    # when a new packet comes in at the controller -- "PACKET-IN"
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

    def flow_example(self, dp):
        # a flow to correctly forward all traffic to m1
        match = parser.OFPMatch(
            # if you want to match on any part of the IP header, you always have
            # to match on the IP type in the ethernet header as well.
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst="44.0.0.0/8",
        )
        action = [parser.OFPActionOutput(4)]
        self.program_flow(dp, match, action, priority=1)

    ##### Task 2 ###################################################################
    def flow_example_groups(self, dp):
        # a flow to correctly forward all traffic to m1, but implemented using
        # group tables

        # you can specify multiple buckets, and each bucket can perform multple
        # actions
        buckets = [
            parser.OFPBucket(actions=[parser.OFPActionOutput(4)]),
        ]
        # create the group
        # docs: https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPGroupMod
        dp.send_msg(
            parser.OFPGroupMod(
                dp,
                command=ofproto.OFPGC_ADD,
                type_=ofproto.OFPGT_SELECT,
                group_id=1,
                buckets=buckets,
            )
        )

        # create a match to send packets to the new group
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="44.0.0.0/8")
        # you've been using this all along, see: self.program_flow in cockpit.py
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionGroup(group_id=1)]
            )
        ]
        dp.send_msg(
            parser.OFPFlowMod(dp, match=match, instructions=instructions, priority=1)
        )

# Basic imports for Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet, arp, ipv4, ipv6

from netaddr import IPAddress, IPNetwork

from controller import CockpitApp

# This is the demo application
#
# We assume the following association between ports and
# connected ASes
#
# Port : AS
#    1 : AS1 (17.0.0.0/8)
#    2 : AS2022
#    3 : AS16
#    4 : AS144


class DemoApplication(CockpitApp):
    """
    A demonstration of a basic controller application

    Helper functions are provided by the super class
    CockpitApp (which can be found in controller.py)
    """

    def __init__(self, *args, **kwargs):
        super(DemoApplication, self).__init__(*args, **kwargs)
        self.info("Demo Application")

        # The total_packets variable keeps track of the
        # number of packets that have been forwarded to the
        # controller.
        self.total_packets = 0
        self.packets_by_ip = dict()

    # This decorator makes sure that the function below is invoked
    # every time a packet arrives at our controller.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        This method is invoked when a packet does not match any
        of the rules deployed on a switch. The controller can
        take subsequent action to update the switch flow table entries
        and handle the packet itself.
        """
        print("pkt in")
        msg = ev.msg
        datapath = msg.datapath
        data = msg.data
        in_port = msg.match["in_port"]

        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, eth, data)
            return

        ip = pkt.get_protocol(ipv4.ipv4)

        if ip is None:
            return

        if self.protect_our_network(datapath, in_port, ip.src, ip.dst):
            return

        self.total_packets += 1

        # Flood all packets so every network can reach every other network
        traffic_type = "all"
        self.send_pkt(datapath, data, port=ofproto.OFPP_FLOOD)

        print(".. total messages received: {:d} ({:s} traffic)".format(
            self.total_packets, traffic_type
        ))

    # This decorator makes sure that the function below is invoked
    # every time a new switch is connected to our controller.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        This method would provide an appropriate hook if we wanted to do
        anything in advance of processing individual packets.
        """
        pass

    def protect_our_network(self, datapath, in_port, src_ip, dst_ip):
        """
        Count packets by IP source addresses and launch countermeasures
        to protect the controller and prevent it from being flooded.
        """
        if src_ip not in self.packets_by_ip:
            self.packets_by_ip[src_ip] = 0
        self.packets_by_ip[src_ip] += 1

        if in_port != 1:
            if self.packets_by_ip[src_ip] == 1000:
                self.launch_countermeasures(datapath, src_ip)
                return True
            if self.packets_by_ip[src_ip] > 1000:
                return True

        if in_port == 1 and self.packets_by_ip.get(dst_ip, 0) > 1000:
            return True

        return False

    def launch_countermeasures(self, datapath, src_ip):
        """
        Deploy a block rule based on IP source addresses
        """
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip
        )
        self.program_flow(datapath, match, [], priority=2)

        warn = f"WARNING! Traffic limit exceeded for IP {format(src_ip)}!"
        warn += " Dropping packets!"
        print(warn)

    def handle_arp(self, datapath, in_port, eth, data):
        """
        Simple ARP forwarding: install a rule for known MACs,
        flood unknown ARP packets.
        """
        ofproto = datapath.ofproto
        src = eth.src

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, eth_dst=src)
        actions = [parser.OFPActionOutput(in_port)]
        self.program_flow(datapath, match, actions, priority=1)

        self.send_pkt(datapath, data, port=ofproto.OFPP_FLOOD)
# =============================================================================
# Task 1.2 - Learning Switch (Double Match Fields)
# Filename: ppsdn26_ujgpb_task12_double.py
# Scenario: learning.yaml

#
# APPROACH: One flow table. Two match fields: eth_src AND eth_dst.
#
# DIFFERENCE from single.py:
# In single.py, one rule covers ALL traffic to a destination, regardless
# of where it came from. Here, rules are per SOURCE-DESTINATION pair.
# This means: one rule for H1->H2, another for H3->H2, etc.
# It is more specific and models individual communication flows exactly.
#
# WHY TWO FIELDS?
# Matching on both src AND dst means we know not just "where to send"
# but also "who is sending". This allows more granular control — you
# could in theory apply different policies for different senders to the
# same destination. For now, we just use it for precise per-flow rules.
# =============================================================================

from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ether_types


class LearningSwitchDouble(CockpitApp):

    def __init__(self, *args, **kwargs):
        super(LearningSwitchDouble, self).__init__(*args, **kwargs)
        self.info("Learning Switch - Double Match Fields")

        # mac_to_port: the learned MAC → port mapping table
        # Structure: { switch_id: { mac_address: port_number } }
        self.mac_to_port = {}

        # installed_flows: tracks which (src, dst) pairs already have a rule
        # so we don't reinstall the same rule for every packet of a flow
        # Structure: { switch_id: set of (src_mac, dst_mac) tuples }
        self.installed_flows = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath

        # Initialise per-switch data structures
        self.mac_to_port[dp.id] = {}
        self.installed_flows[dp.id] = set()
        print(f"Switch {dp.id} connected - Learning Switch (Double) ready")

        # Default rule: send all unmatched packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.program_flow(dp, match, actions, priority=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        data = msg.data

        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP link-layer discovery packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # -----------------------------------------------------------------
        # LEARNING STEP: record src_mac → in_port mapping
        # -----------------------------------------------------------------
        if src_mac not in self.mac_to_port[dp.id]:
            self.mac_to_port[dp.id][src_mac] = in_port
            print(f"Learned: MAC {src_mac} is on port {in_port}")

        # -----------------------------------------------------------------
        # FORWARDING STEP: do we know where dst_mac is?
        # -----------------------------------------------------------------
        if dst_mac in self.mac_to_port[dp.id]:
            out_port = self.mac_to_port[dp.id][dst_mac]

            # DOUBLE: install a rule matching on BOTH eth_src AND eth_dst.
            # This creates one rule per unique (sender, receiver) pair.
            # We track installed flows to avoid reinstalling the same rule.
            flow_key = (src_mac, dst_mac)
            if flow_key not in self.installed_flows[dp.id]:
                match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                actions = [parser.OFPActionOutput(out_port)]
                self.program_flow(dp, match, actions, priority=1)
                self.installed_flows[dp.id].add(flow_key)
                print(f"Flow installed: {src_mac} -> {dst_mac} via port {out_port}")
            else:
                # Rule already installed — this is a stray packet that arrived
                # before the switch applied the rule. Just forward it manually.
                print(f"Stray packet: {src_mac} -> {dst_mac}, forwarding to port {out_port}")
        else:
            # Destination unknown — flood and wait to learn it
            out_port = ofproto.OFPP_FLOOD
            print(f"Unknown dst {dst_mac} - flooding")

        # Forward the packet that triggered this handler
        self.send_pkt(dp, data, port=out_port)
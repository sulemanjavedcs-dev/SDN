# =============================================================================
# Task 1.2 - Learning Switch (Single Match Field)
# Filename: ppsdn26_ujgpb_task12_single.py
# Scenario: learning.yaml

#
# APPROACH: One flow table. One match field: eth_dst (destination MAC only).
#
# HOW A LEARNING SWITCH WORKS:
# A normal switch doesn't know which host is on which port. It has to LEARN
# by watching traffic. Every packet has a SOURCE MAC address. By reading that,
# we learn: "this MAC address lives on this port". We store this in a table.
# When a packet arrives for a DESTINATION we already know, we install a flow
# rule so future packets go directly to the right port without bothering us.
# If we don't know the destination yet, we flood (send everywhere) and wait.
#
# SINGLE approach specifics:
# Flow rules match ONLY on eth_dst (destination MAC address).
# One rule per destination host — simple, clean, minimal rules.
# =============================================================================

from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ether_types


class LearningSwitchSingle(CockpitApp):

    def __init__(self, *args, **kwargs):
        super(LearningSwitchSingle, self).__init__(*args, **kwargs)
        self.info("Learning Switch - Single Match Field")

        # mac_to_port is our forwarding table (the "learned" knowledge).
        # Structure: { switch_id: { mac_address: port_number } }
        # Example after learning: { 1: { "00:00:00:00:00:01": 1, ... } }
        self.mac_to_port = {}

    # Called when a switch connects. We set up the default flow rule:
    # "if no other rule matches, send the packet to the controller".
    # This is what makes learning possible — unknown packets come to us.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath

        # Initialise an empty MAC table for this switch
        self.mac_to_port[dp.id] = {}
        print(f"Switch {dp.id} connected - Learning Switch (Single) ready")

        # Default rule: match everything, send to controller, priority=0
        # The parent CockpitApp already installs this, but we set it
        # explicitly with FLOOD as fallback so unknown packets are flooded,
        # not just sent to controller (we handle that in packet_in_handler)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.program_flow(dp, match, actions, priority=0)

    # Called every time a packet arrives that no flow rule matched.
    # This is where learning and rule installation happens.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        data = msg.data

        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # LLDP is a link-layer discovery protocol used internally — ignore it
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src   # who sent this packet
        dst_mac = eth.dst   # who this packet is for

        # -----------------------------------------------------------------
        # LEARNING STEP: record that src_mac lives on in_port
        # Every packet tells us something: "the sender of this packet
        # is reachable via the port it arrived on."
        # -----------------------------------------------------------------
        if src_mac not in self.mac_to_port[dp.id]:
            self.mac_to_port[dp.id][src_mac] = in_port
            print(f"Learned: MAC {src_mac} is on port {in_port}")

        # -----------------------------------------------------------------
        # FORWARDING STEP: do we know where dst_mac is?
        # -----------------------------------------------------------------
        if dst_mac in self.mac_to_port[dp.id]:
            out_port = self.mac_to_port[dp.id][dst_mac]

            # SINGLE: install a flow rule matching ONLY on eth_dst.
            # This means: "any future packet destined to this MAC
            # should go directly to out_port, without asking us."
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            # priority=1 overrides the default "send to controller" rule
            self.program_flow(dp, match, actions, priority=1)
            print(f"Flow installed: eth_dst={dst_mac} -> port {out_port}")
        else:
            # We don't know where this destination is yet.
            # Flood: send on all ports except the one it came in on.
            out_port = ofproto.OFPP_FLOOD
            print(f"Unknown dst {dst_mac} - flooding")

        # Forward the current packet (the one that triggered this handler).
        # Newly installed flow rules only apply to FUTURE packets.
        self.send_pkt(dp, data, port=out_port)
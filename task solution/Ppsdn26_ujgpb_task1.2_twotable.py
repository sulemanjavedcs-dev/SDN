# =============================================================================
# Task 1.2 - Learning Switch (Two Flow Tables)
# Filename: ppsdn26_ujgpb_task12_twotable.py
#
# APPROACH: TWO flow tables with OFPInstructionGotoTable.
#
#   Table 0 — LEARNING TABLE:
#     Purpose: decide whether the controller needs to see this packet.
#     - If the source MAC is UNKNOWN: send to controller (so we can learn)
#                                     then continue to Table 1 for forwarding
#     - If the source MAC is KNOWN:   skip controller, go directly to Table 1
#
#   Table 1 — FORWARDING TABLE:
#     Purpose: decide where to send the packet.
#     - If the destination MAC is KNOWN: send to the correct port
#     - If the destination MAC is UNKNOWN: flood on all ports
#
# WHY TWO TABLES?
# It cleanly separates two concerns: "should I learn from this?" (Table 0)
# and "where should this go?" (Table 1). Once a source is known, Table 0
# stops sending packets to the controller entirely — more efficient.
# The key OpenFlow instruction is OFPInstructionGotoTable which passes
# a packet from one table to the next.
# =============================================================================

from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ether_types

# Table IDs — named constants so the code is self-documenting
TABLE_LEARNING = 0    # Table 0: decides if controller needs to see the packet
TABLE_FORWARDING = 1  # Table 1: decides which port to send the packet out


class LearningSwitchTwoTable(CockpitApp):

    def __init__(self, *args, **kwargs):
        super(LearningSwitchTwoTable, self).__init__(*args, **kwargs)
        self.info("Learning Switch - Two Tables")

        # mac_to_port: learned MAC → port mapping
        # Structure: { switch_id: { mac_address: port_number } }
        self.mac_to_port = {}

    def install_table_flow(self, dp, table_id, match, instructions, priority=0):
        """
        Helper to install a flow rule into a SPECIFIC table (not just table 0).
        The standard program_flow() from CockpitApp always writes to table 0,
        so we need this custom helper to write to table 1.
        """
        flowmod = parser.OFPFlowMod(
            datapath=dp,
            table_id=table_id,      # which table this rule goes into
            match=match,
            instructions=instructions,
            priority=priority
        )
        dp.send_msg(flowmod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath

        self.mac_to_port[dp.id] = {}
        print(f"Switch {dp.id} connected - Learning Switch (Two Table) ready")

        # -----------------------------------------------------------------
        # TABLE 0 default rule (priority 0):
        # For any packet with an UNKNOWN source MAC (no specific rule yet),
        # send a copy to the controller for learning, THEN pass to Table 1.
        #
        # OFPIT_APPLY_ACTIONS: execute these actions immediately
        # OFPInstructionGotoTable: after actions, pass packet to Table 1
        # -----------------------------------------------------------------
        match = parser.OFPMatch()
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
            ),
            parser.OFPInstructionGotoTable(TABLE_FORWARDING)
        ]
        self.install_table_flow(dp, TABLE_LEARNING, match, instructions, priority=0)

        # -----------------------------------------------------------------
        # TABLE 1 default rule (priority 0):
        # For any packet with an UNKNOWN destination MAC, flood it.
        # Once we learn the destination, we'll add a specific rule above
        # this default that sends it to the correct port.
        # -----------------------------------------------------------------
        match = parser.OFPMatch()
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            )
        ]
        self.install_table_flow(dp, TABLE_FORWARDING, match, instructions, priority=0)

        print("Default rules installed in both tables")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        data = msg.data

        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets (link-layer discovery, not real traffic)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # -----------------------------------------------------------------
        # LEARNING STEP: record src_mac → in_port
        # This packet reached us because Table 0 had no specific rule for
        # this source MAC yet — meaning this is a NEW (previously unseen) host.
        # -----------------------------------------------------------------
        if src_mac not in self.mac_to_port[dp.id]:
            self.mac_to_port[dp.id][src_mac] = in_port
            print(f"Learned: MAC {src_mac} is on port {in_port}")

            # Now that we know this source, update Table 0:
            # "for packets FROM this MAC, skip the controller and go to Table 1"
            # This prevents future packets from the same source reaching us again.
            match = parser.OFPMatch(eth_src=src_mac)
            instructions = [
                parser.OFPInstructionGotoTable(TABLE_FORWARDING)
                # No controller action — source is known, learning is done
            ]
            self.install_table_flow(dp, TABLE_LEARNING, match, instructions, priority=1)
            print(f"Table 0 updated: {src_mac} known -> skip controller")

        # -----------------------------------------------------------------
        # FORWARDING STEP: install a rule in Table 1 if dst is now known
        # -----------------------------------------------------------------
        if dst_mac in self.mac_to_port[dp.id]:
            out_port = self.mac_to_port[dp.id][dst_mac]

            # Update Table 1: "for packets TO this dst MAC, send to out_port"
            # This overrides the default flood rule for this specific dst.
            match = parser.OFPMatch(eth_dst=dst_mac)
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(out_port)]
                )
            ]
            self.install_table_flow(dp, TABLE_FORWARDING, match, instructions, priority=1)
            print(f"Table 1 updated: eth_dst={dst_mac} -> port {out_port}")

            # Forward this packet manually (the rule only helps future packets)
            self.send_pkt(dp, data, port=out_port)
        else:
            # Destination not yet known — flood and wait
            print(f"Unknown dst {dst_mac} - flooding")
            self.send_pkt(dp, data, port=ofproto.OFPP_FLOOD)
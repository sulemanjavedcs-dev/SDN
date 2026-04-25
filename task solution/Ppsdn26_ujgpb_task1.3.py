# =============================================================================
# Task 1.3 - Priority-Based Filtering
#
# PROBLEM:
#   N1 sends IP packets to N2 and N3. Most are fine (src=11.0.0.0/8).
#   But some are misconfigured — they leak from a private subnet (src=10.0.0.0/8).
#   We must DROP all packets with private source addresses, even if their
#   destination would normally be valid.
#
# PRIORITY DESIGN (most important part of this task):
#
#   Priority 2 — DROP rule for private source (10.0.0.0/8)
#     Highest priority so it is checked FIRST. Any packet with a private
#     source IP is dropped immediately, before any forwarding rule can match.
#
#   Priority 1 — Forward rules for valid destinations
#     Only reached if the packet passed the priority-2 check (i.e., src is NOT
#     from the private subnet). Routes traffic correctly to N2 or N3.
#
#   Priority 0 — Default drop rule
#     As required by the assignment ("use priority 0 for default flows").
#     Any packet not matched by priority 1 or 2 rules is dropped silently.
#

# =============================================================================

from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import ether_types


class PriorityFilter(CockpitApp):

    def __init__(self, *args, **kwargs):
        super(PriorityFilter, self).__init__(*args, **kwargs)
        self.info("Priority-Based Filtering - Task 1.3")

    # All rules are installed proactively the moment the switch connects.
    # No packet_in_handler needed — the switch handles everything itself.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print(f"Switch {datapath.id} connected - installing priority filter rules")

        # -----------------------------------------------------------------
        # PRIORITY 0 — Default drop rule
        # Matches ALL packets (empty OFPMatch = wildcard match).
        # An empty action list [] means DROP — packet is discarded.
        # This is the "catch-all" safety net: anything not explicitly
        # forwarded by priority-1 rules gets dropped here.
        # Assignment requires: "use priority 0 for default flows"
        # -----------------------------------------------------------------
        match_default = parser.OFPMatch()
        self.program_flow(datapath, match_default, actions=[], priority=0)
        print("Rule installed: priority=0 | match=ALL | action=DROP (default)")

        # -----------------------------------------------------------------
        # PRIORITY 1 — Forward valid traffic to N2 (dst=22.0.0.0/8 → port 2)
        # Only packets that didn't match the priority-2 block rule reach here.
        # eth_type=ETH_TYPE_IP is REQUIRED — assignment says IP-only matching.
        # The bitmask '255.0.0.0' matches any IP where first 8 bits = 22,
        # i.e., the entire 22.x.x.x range.
        # -----------------------------------------------------------------
        match_to_n2 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=('22.0.0.0', '255.0.0.0')
        )
        actions_to_n2 = [parser.OFPActionOutput(2)]
        self.program_flow(datapath, match_to_n2, actions_to_n2, priority=1)
        print("Rule installed: priority=1 | dst=22.0.0.0/8 | action=port 2 (N2)")

        # -----------------------------------------------------------------
        # PRIORITY 1 — Forward valid traffic to N3 (dst=33.0.0.0/8 → port 3)
        # Same logic as above, mirrored for N3.
        # -----------------------------------------------------------------
        match_to_n3 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=('33.0.0.0', '255.0.0.0')
        )
        actions_to_n3 = [parser.OFPActionOutput(3)]
        self.program_flow(datapath, match_to_n3, actions_to_n3, priority=1)
        print("Rule installed: priority=1 | dst=33.0.0.0/8 | action=port 3 (N3)")

        # -----------------------------------------------------------------
        # PRIORITY 2 — Block (DROP) all packets from private subnet 10.0.0.0/8
        # This is the HIGHEST priority rule. It is checked BEFORE the
        # forwarding rules above. Any packet with src IP in 10.x.x.x is
        # dropped immediately — even if its destination is 22.x.x.x or 33.x.x.x.
        #
        # WHY priority 2 beats priority 1:
        # A packet with src=10.x.x.x and dst=22.x.x.x matches BOTH:
        #   - priority 1 rule (dst=22.x.x.x → forward to N2)
        #   - priority 2 rule (src=10.x.x.x → DROP)
        # OpenFlow always applies the HIGHEST priority matching rule.
        # So priority 2 wins → packet is dropped. Correct!
        # -----------------------------------------------------------------
        match_block_private = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=('10.0.0.0', '255.0.0.0')   # match source in 10.x.x.x
        )
        self.program_flow(datapath, match_block_private, actions=[], priority=2)
        print("Rule installed: priority=2 | src=10.0.0.0/8 | action=DROP (block private)")

        print("All rules installed. Switch ready.")
        print("  Priority 0: default drop")
        print("  Priority 1: forward 22.0.0.0/8->port2, 33.0.0.0/8->port3")
        print("  Priority 2: drop all src=10.0.0.0/8")
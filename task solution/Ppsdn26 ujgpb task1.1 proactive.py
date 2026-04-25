# =============================================================================
# Task 1.1 - Proactive Flow Programming
# Filename: ppsdn26_ujgpb_task11_proactive.py
# Scenario: forwarding.yaml
#
# PROACTIVE means: flow rules are installed BEFORE any packet arrives.
# The moment the switch connects to the controller, we immediately tell it
# exactly what to do with every packet — no need to ask us later.
# =============================================================================

from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import ether_types


class ProactiveForwarding(CockpitApp):

    def __init__(self, *args, **kwargs):
        super(ProactiveForwarding, self).__init__(*args, **kwargs)
        self.info("Proactive Forwarding - Task 1.1")

    # This function is called automatically by Ryu the moment a switch
    # connects to our controller. CONFIG_DISPATCHER means "switch is
    # setting up" — this is exactly the right time to install proactive rules.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # datapath = the connection object to talk to this specific switch
        datapath = ev.msg.datapath
        print(f"Switch {datapath.id} connected - installing proactive flows")

        # ---------------------------------------------------------------------
        # Rule 1: Forward traffic destined to N2 (22.0.0.0/8) out of port 2
        #
        # OFPMatch with eth_type=ETH_TYPE_IP is REQUIRED by the assignment:
        # "all flow rules should exclusively use IP for matching"
        # The bitmask '255.0.0.0' means: match ANY IP where the first 8 bits
        # equal 22 — i.e., the entire 22.x.x.x range, not just one host.
        # ---------------------------------------------------------------------
        match_to_n2 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,       # match only IPv4 packets
            ipv4_dst=('22.0.0.0', '255.0.0.0')      # destination in 22.0.0.0/8
        )
        actions_to_n2 = [parser.OFPActionOutput(2)]  # send out port 2 (to N2)
        # priority=1 so this rule takes priority over the default "send to
        # controller" rule (priority=0) installed by our parent CockpitApp
        self.program_flow(datapath, match_to_n2, actions_to_n2, priority=1)

        # ---------------------------------------------------------------------
        # Rule 2: Forward traffic destined to N1 (11.0.0.0/8) out of port 1
        # Same logic as above but mirrored for the other direction.
        # ---------------------------------------------------------------------
        match_to_n1 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,       # match only IPv4 packets
            ipv4_dst=('11.0.0.0', '255.0.0.0')      # destination in 11.0.0.0/8
        )
        actions_to_n1 = [parser.OFPActionOutput(1)]  # send out port 1 (to N1)
        self.program_flow(datapath, match_to_n1, actions_to_n1, priority=1)

        print("Proactive flows installed:")
        print("  11.0.0.0/8 -> port 1 (N1)")
        print("  22.0.0.0/8 -> port 2 (N2)")
        # From this point on, the switch handles ALL packets on its own.
        # The controller will never be involved again for these traffic flows.
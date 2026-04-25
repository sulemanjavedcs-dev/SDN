# =============================================================================
# Task 1.4 - Timeout-Based Mirroring
# Filename: ppsdn26_ujgpb_task14.py

# TASK DESCRIPTION:
#   - Forward valid traffic: dst=22.x.x.x → N2, dst=33.x.x.x → N3
#   - When a packet arrives for ANY OTHER destination (unknown/suspicious):
#       1. Identify the /8 subnet of the destination IP
#       2. Redirect ALL traffic to that subnet to N4 (for monitoring) for 4 seconds
#       3. After 4 seconds, DROP all traffic to that subnet permanently
#
# KEY DESIGN — TWO RULES INSTALLED SIMULTANEOUSLY:
#
#   Priority 3 (mirror):  dst=suspect_subnet → N4  [hard_timeout=4s]
#   Priority 2 (drop):    dst=suspect_subnet → DROP [permanent, no timeout]
#
#   While the mirror rule is active (first 4 seconds):
#     Priority 3 wins → packets go to N4 ✅
#
#   After 4 seconds, mirror rule expires automatically:
#     Priority 2 (drop) takes over → packets dropped permanently ✅
#
#   This elegant design means we NEVER need to listen for flow-expiry events.
#   The switch handles the transition by itself using OpenFlow priorities.
#
# TIMEOUT TYPES:
#   hard_timeout = absolute time limit — rule is deleted after N seconds
#                  regardless of whether packets are flowing or not.
#                  This is the RIGHT timeout for mirroring (we want exactly 4s).
#   idle_timeout = time since LAST matched packet — would reset if traffic flows,
#                  which would make mirroring last LONGER than 4s. Wrong for us.
#

# =============================================================================

from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ipv4, ether_types


class TimedMirror(CockpitApp):

    def __init__(self, *args, **kwargs):
        super(TimedMirror, self).__init__(*args, **kwargs)
        self.info("Timeout-Based Mirroring - Task 1.4")

        # Track which /8 subnets we have already installed rules for.
        # Prevents reinstalling the same mirror+drop rules if multiple
        # packets for the same suspicious subnet arrive before the first
        # rule takes effect on the switch.
        self.mirrored_subnets = set()

    # Proactive setup: install forwarding rules for valid destinations
    # as soon as the switch connects, before any packet arrives.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print(f"Switch {datapath.id} connected - installing base forwarding rules")

        # -----------------------------------------------------------------
        # Priority 0 — Default: send unknown packets to controller
        # This is what allows suspicious packets to reach packet_in_handler.
        # Any packet not matched by the priority-1 rules below comes here.
        # -----------------------------------------------------------------
        match_default = parser.OFPMatch()
        actions_to_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                   ofproto.OFPCML_NO_BUFFER)]
        self.program_flow(datapath, match_default, actions_to_ctrl, priority=0)

        # -----------------------------------------------------------------
        # Priority 1 — Forward valid traffic to N2 (dst=22.0.0.0/8 → port 2)
        # eth_type=ETH_TYPE_IP required — "exclusively use IP for matching"
        # -----------------------------------------------------------------
        match_to_n2 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=('22.0.0.0', '255.0.0.0')
        )
        self.program_flow(datapath, match_to_n2,
                          [parser.OFPActionOutput(2)], priority=1)
        print("Rule: priority=1 | dst=22.0.0.0/8 → port 2 (N2)")

        # -----------------------------------------------------------------
        # Priority 1 — Forward valid traffic to N3 (dst=33.0.0.0/8 → port 3)
        # -----------------------------------------------------------------
        match_to_n3 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=('33.0.0.0', '255.0.0.0')
        )
        self.program_flow(datapath, match_to_n3,
                          [parser.OFPActionOutput(3)], priority=1)
        print("Rule: priority=1 | dst=33.0.0.0/8 → port 3 (N3)")
        print("Base rules installed. Waiting for suspicious traffic...")

    # Called whenever a packet reaches the controller (no matching flow rule).
    # This only happens for packets NOT destined to N2 or N3 (those are
    # handled by priority-1 rules and never reach us).
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        data = msg.data

        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Only handle IPv4 packets — ignore ARP, LLDP, etc.
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            return

        dst_ip = ip.dst

        # -----------------------------------------------------------------
        # STEP 1: Identify the /8 subnet of the suspicious destination IP.
        #
        # We extract only the first octet (e.g., "10" from "10.5.3.2")
        # and build the /8 network base (e.g., "10.0.0.0").
        # This is what the assignment means by "the /8 subnet containing
        # the IP address" — e.g., 10.1.2.3 → 10.0.0.0/8
        # -----------------------------------------------------------------
        first_octet = dst_ip.split('.')[0]
        subnet_base = f"{first_octet}.0.0.0"
        subnet_mask = "255.0.0.0"
        subnet_key = f"{subnet_base}/8"

        # Skip if we already installed rules for this subnet.
        # (Handles race condition: multiple packets arriving before rule takes effect)
        if subnet_key in self.mirrored_subnets:
            # Stray packet — rule is already installed, just forward to N4 manually
            self.send_pkt(datapath, data, port=4)
            return

        # Mark this subnet as handled before installing rules
        self.mirrored_subnets.add(subnet_key)
        print(f"Suspicious traffic detected! dst={dst_ip} → subnet={subnet_key}")

        # -----------------------------------------------------------------
        # STEP 2: Install MIRROR rule (priority 3, hard_timeout=4 seconds)
        #
        # Redirects ALL traffic to this /8 subnet to N4 (port 4) for 4s.
        # hard_timeout=4 means the rule is automatically deleted after exactly
        # 4 seconds, regardless of how much traffic is flowing.
        # (idle_timeout would be wrong here — it resets on each packet,
        #  meaning busy traffic would extend mirroring beyond 4 seconds)
        # -----------------------------------------------------------------
        match_suspect = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=(subnet_base, subnet_mask)
        )
        mirror_actions = [parser.OFPActionOutput(4)]  # port 4 = N4 (monitor)
        self.program_flow(
            datapath,
            match_suspect,
            mirror_actions,
            priority=3,
            hard_timeout=4,   # expires after exactly 4 seconds
            idle_timeout=0    # don't use idle timeout
        )
        print(f"Mirror rule installed: dst={subnet_key} → N4 (port 4) for 4 seconds")

        # -----------------------------------------------------------------
        # STEP 3: Install DROP rule (priority 2, permanent — no timeout)
        #
        # This rule sits BELOW the mirror rule (priority 2 < priority 3).
        # While mirror is active: priority 3 wins → packets go to N4.
        # After 4 seconds when mirror expires: priority 2 takes over → DROP.
        #
        # An empty action list [] means drop in OpenFlow.
        # This rule never expires (hard_timeout=0, idle_timeout=0).
        # -----------------------------------------------------------------
        self.program_flow(
            datapath,
            match_suspect,
            actions=[],       # empty = DROP
            priority=2,
            hard_timeout=0,   # permanent — never expires
            idle_timeout=0
        )
        print(f"Drop rule installed: dst={subnet_key} → DROP (permanent, activates after 4s)")

        # -----------------------------------------------------------------
        # STEP 4: Forward THIS packet to N4 manually.
        # The flow rules just installed only apply to FUTURE packets.
        # This first suspicious packet must be forwarded explicitly.
        # -----------------------------------------------------------------
        self.send_pkt(datapath, data, port=4)
        print(f"First suspicious packet manually forwarded to N4")
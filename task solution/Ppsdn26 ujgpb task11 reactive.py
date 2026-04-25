# =============================================================================
# Task 1.1 - Reactive Flow Programming
# Filename: ppsdn26_ujgpb_task11_reactive.py
# Scenario: forwarding.yaml
#
# REACTIVE means: the controller waits and only acts when a packet arrives
# that the switch doesn't know how to handle yet. The controller inspects
# the packet, decides what to do, installs a flow rule for future packets
# of the same type, and then manually forwards this first packet.
#
# After the first packet of a given flow, the switch handles everything
# itself — the controller is no longer involved for that flow.
# =============================================================================

from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
from netaddr import IPAddress, IPNetwork


class ReactiveForwarding(CockpitApp):

    def __init__(self, *args, **kwargs):
        super(ReactiveForwarding, self).__init__(*args, **kwargs)
        self.info("Reactive Forwarding - Task 1.1")

        # This set tracks which subnets we have ALREADY installed a rule for.
        # Without this, we would reinstall the same flow rule for every single
        # packet of the same flow — wasteful and incorrect behaviour.
        # Once a subnet is in this set, we skip rule installation and just
        # forward the stray packet that arrived before the rule took effect.
        self.installed_subnets = set()

    # CONFIG_DISPATCHER: called when switch first connects.
    # We do nothing proactively here — we just let the parent class install
    # the default "send all unmatched packets to controller" rule, which is
    # what triggers our packet_in_handler below for every new flow.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print(f"Switch {datapath.id} connected - waiting for packets reactively")

    # MAIN_DISPATCHER: called every time a packet arrives at the controller.
    # This happens because the switch has no matching flow rule yet, so it
    # sends the packet up to us to decide what to do.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        data = msg.data

        # Parse the raw packet bytes into a structured object we can inspect
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Assignment requires: "all flow rules should exclusively use IP"
        # So we ignore everything that is not an IPv4 packet (e.g. ARP)
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        # Extract the IPv4 layer from the packet to read the destination IP
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:
            return

        dst_ip = ip.dst

        # ---------------------------------------------------------------------
        # Decide which port and subnet this packet belongs to, based on
        # the destination IP address.
        # ---------------------------------------------------------------------
        if IPAddress(dst_ip) in IPNetwork('22.0.0.0/8'):
            out_port = 2
            # The subnet tuple format (ip, mask) is required by OFPMatch
            # for prefix-based matching — matches all of 22.x.x.x
            subnet = ('22.0.0.0', '255.0.0.0')
            subnet_key = '22.0.0.0/8'

        elif IPAddress(dst_ip) in IPNetwork('11.0.0.0/8'):
            out_port = 1
            subnet = ('11.0.0.0', '255.0.0.0')
            subnet_key = '11.0.0.0/8'

        else:
            # Packet is not destined for either known network — drop silently
            return

        # ---------------------------------------------------------------------
        # Install a flow rule ONLY if we haven't done so already for this
        # subnet. This is the KEY FIX for the reactive controller:
        #
        # Without this check, every packet that arrives at the controller
        # before the flow rule takes effect (there is always a tiny delay
        # between installing a rule and the switch applying it) would cause
        # us to install the same rule again and again — spamming the switch.
        #
        # With this check: install once, remember it, skip on future packets.
        # ---------------------------------------------------------------------
        if subnet_key not in self.installed_subnets:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,   # IP-only matching as required
                ipv4_dst=subnet                      # match entire /8 subnet
            )
            actions = [parser.OFPActionOutput(out_port)]
            # priority=1 overrides the default "send to controller" rule (priority=0)
            self.program_flow(datapath, match, actions, priority=1)

            # Mark this subnet as done so we never install this rule again
            self.installed_subnets.add(subnet_key)
            print(f"Reactive: new flow rule installed for {subnet_key} -> port {out_port}")
        else:
            # Rule already installed — this is just a stray packet that arrived
            # at the controller before the switch applied the new rule.
            # We simply forward it manually and move on.
            print(f"Reactive: stray packet for {subnet_key} -> forwarding manually to port {out_port}")

        # ---------------------------------------------------------------------
        # Manually forward THIS packet (the one that triggered this handler).
        # The flow rule only affects FUTURE packets. This first one (and any
        # stragglers) must be forwarded by the controller explicitly.
        # ---------------------------------------------------------------------
        self.send_pkt(datapath, data, port=out_port)
from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub


class Task21(CockpitApp):

    # -------------------------------------------------------------------------
    # ROUTING TABLE 
    # -------------------------------------------------------------------------
    ROUTING_TABLE = {
        1: {'11.0.0.0/8': 4,   
            '22.0.0.0/8': 3,   
            '33.0.0.0/8': 3,   
            '44.0.0.0/8': 2},  

        2: {'11.0.0.0/8': 1,   
            '22.0.0.0/8': 2,  
            '33.0.0.0/8': 2,   
            '44.0.0.0/8': 3},  

        3: {'11.0.0.0/8': 1,   
            '22.0.0.0/8': 3,   
            '33.0.0.0/8': 3,   
            '44.0.0.0/8': 4},  

        4: {'11.0.0.0/8': 1,   
            '22.0.0.0/8': 5,   
            '33.0.0.0/8': 4,   
            '44.0.0.0/8': 3},  

        5: {'11.0.0.0/8': 2,   
            '22.0.0.0/8': 2,   
            '33.0.0.0/8': 3,   
            '44.0.0.0/8': 4},  

        6: {'11.0.0.0/8': 1,   
            '22.0.0.0/8': 2,   
            '33.0.0.0/8': 5,   
            '44.0.0.0/8': 4},  

        7: {'11.0.0.0/8': 2,   
            '22.0.0.0/8': 2,  
            '33.0.0.0/8': 3,   
            '44.0.0.0/8': 4},  

        8: {'11.0.0.0/8': 2,   
            '22.0.0.0/8': 2,   
            '33.0.0.0/8': 4,   
            '44.0.0.0/8': 3},  
    }

    # -------------------------------------------------------------------------
    # SPANNING TREE PORTS — loop-free ARP forwarding
    #
    # This is a mesh topology. Flooding ARP on all ports causes broadcast loops
    # — the same packet circulates through multiple paths, hosts miss replies,
    # -------------------------------------------------------------------------
    SPANNING_TREE_PORTS = {
        1: {1, 2, 3, 4},   # to s2(p1), s3(p2), s4(p3), H1(p4)
        2: {1, 3},          # to s1(p1), s5(p3)
        3: {1, 5},          # to s1(p1), s6(p5)
        4: {1, 4, 5},       # to s1(p1), s8(p4), H2(p5)
        5: {1, 4},          # to s2(p1), s7(p4)
        6: {1},             # to s3(p1) — leaf in spanning tree
        7: {1, 4},          # to s5(p1), H4(p4)
        8: {1, 4},          # to s4(p1), H3(p4)
    }

    POLL_INTERVAL = 5

    def __init__(self, *args, **kwargs):
        super(Task21, self).__init__(*args, **kwargs)
        self.info("Task 2.1 - Monitoring")

        self.datapaths = {}
        self.current_stats = {}
        self.pending_replies = 0

        # Start concurrent monitoring greenthread using ryu hub (required by task)
        hub.spawn(self._monitor_loop)

    # =========================================================================
    # Switch connects — install all IP routing rules proactively
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        # Install one IP forwarding rule per destination subnet.
        # Priority 10 beats the default table-miss (priority 0) from CockpitApp
        # so matched packets go to the right port without hitting the controller.
        if dpid in self.ROUTING_TABLE:
            for ip_dst, out_port in self.ROUTING_TABLE[dpid].items():
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=ip_dst
                )
                actions = [parser.OFPActionOutput(out_port)]
                self.program_flow(datapath, match, actions, priority=10)

            print(f"S{dpid}: {len(self.ROUTING_TABLE[dpid])} routing rules installed")

    # =========================================================================
    # Packet-in — ARP forwarded on spanning tree only (prevents broadcast loops)
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Only ARP reaches the controller — IP is handled by flow rules.
        # Forward ARP only on spanning tree ports to avoid broadcast loops.
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            tree_ports = self.SPANNING_TREE_PORTS.get(dpid, set())
            for port in tree_ports:
                if port != in_port:
                    self.send_pkt(datapath, msg.data, port)

    # =========================================================================
    # Monitoring greenthread — polls all switches every POLL_INTERVAL seconds
    # =========================================================================
    def _monitor_loop(self):
        hub.sleep(self.POLL_INTERVAL)
        while True:
            if self.datapaths:
                self.pending_replies = len(self.datapaths)
                self.current_stats = {}
                for dp in list(self.datapaths.values()):
                    req = parser.OFPFlowStatsRequest(dp)
                    dp.send_msg(req)
            hub.sleep(self.POLL_INTERVAL)

    # =========================================================================
    # Flow stats reply — delivered asynchronously by Ryu per switch
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        # Skip the default table-miss rule (priority 0), keep only our rules
        self.current_stats[dpid] = [
            stat for stat in ev.msg.body if stat.priority > 0
        ]
        self.pending_replies -= 1

        if self.pending_replies <= 0:
            self._display_stats()

    # =========================================================================
    # Textual visualization — clears and reprints every polling round
    # =========================================================================
    def _display_stats(self):
        print('$SDNC_CLEAR_SCREEN$')
        print('=' * 62)
        print('  NETWORK TRAFFIC MONITOR  —  Task 2.1')
        print('=' * 62)

        for dpid in sorted(self.current_stats.keys()):
            flows = self.current_stats[dpid]

            print(f'\n  [ Switch S{dpid} ]')
            print(f"  {'Destination':<20} {'Port':>6} {'Packets':>10} {'Bytes':>12}")
            print(f"  {'-'*52}")

            if not flows:
                print('  (no active flows yet)')
                continue

            for stat in sorted(flows, key=lambda s: str(s.match.get('ipv4_dst', ''))):
                # Convert tuple ('11.0.0.0','255.0.0.0') → clean '11.0.0.0/8'
                raw = stat.match.get('ipv4_dst', 'N/A')
                ip_dst = f"{raw[0]}/8" if isinstance(raw, tuple) else str(raw)

                out_port = 'N/A'
                if stat.instructions:
                    acts = getattr(stat.instructions[0], 'actions', [])
                    if acts:
                        out_port = str(acts[0].port)

                print(
                    f"  {ip_dst:<20} {out_port:>6}"
                    f" {stat.packet_count:>10} {stat.byte_count:>12}"
                )

        print('\n' + '=' * 62)
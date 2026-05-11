from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub  # required for concurrent monitoring


class Task22(CockpitApp):

    # -------------------------------------------------------------------------
    # TOPOLOGY —
    # Each entry: (switch_a, switch_b, port_on_a, port_on_b)
    # -------------------------------------------------------------------------
    LINKS = [
        (1, 2, 1, 1), (1, 3, 2, 1), (1, 4, 3, 1),
        (2, 3, 2, 2), (2, 5, 3, 1),
        (3, 4, 3, 2), (3, 5, 4, 2), (3, 6, 5, 1),
        (4, 6, 3, 2), (4, 8, 4, 1),
        (5, 6, 3, 3), (5, 7, 4, 1),
        (6, 7, 4, 2), (6, 8, 5, 2),
        (7, 8, 3, 3),
    ]

    # Host attachment: subnet → (switch_dpid, host_port_on_switch)
    HOSTS = {
        '11.0.0.0/8': (1, 4),   
        '22.0.0.0/8': (4, 5),   
        '33.0.0.0/8': (8, 4),   
        '44.0.0.0/8': (7, 4),   
    }

    # -------------------------------------------------------------------------
    # SPANNING TREE PORTS — loop-free ARP forwarding
    #
    # Mesh topology needs spanning tree for ARP. Flooding all ports causes
    # broadcast loops — hosts miss ARP replies and ping fails.
    # Spanning tree edges (BFS from s1): s1-s2, s1-s3, s1-s4, s2-s5,
    #                                     s3-s6, s5-s7, s4-s8
    # -------------------------------------------------------------------------
    SPANNING_TREE_PORTS = {
        1: {1, 2, 3, 4},   
        2: {1, 3},          
        3: {1, 5},          
        4: {1, 4, 5},      
        5: {1, 4},          
        6: {1},             
        7: {1, 4},         
        8: {1, 4},         
    }

    POLL_INTERVAL = 5

    def __init__(self, *args, **kwargs):
        super(Task22, self).__init__(*args, **kwargs)
        self.info("Task 2.2 - Shortest Path Routing")

        # Compute routing table using BFS (shortest path by hop count).
        # This is equivalent to Dijkstra with uniform edge weights.
        # We use native Python BFS instead of networkx because networkx is
        # not installed in the SDN-Cockpit virtual machine environment.
        self.routing_table = self._compute_routing_table()
        self._print_routing_table()

        self.datapaths = {}
        self.current_stats = {}
        self.pending_replies = 0

        # Start concurrent monitoring greenthread (reused from Task 2.1)
        hub.spawn(self._monitor_loop)

    # =========================================================================
    # BFS shortest path — finds minimum hop path from every switch to every host
    # Algorithm: standard BFS from source switch to destination switch.
    # The first path found is always the shortest (fewest hops).
    # We record path[1] as next_hop, then look up the local port to next_hop.
    # =========================================================================
    def _compute_routing_table(self):
        routing = {}

        for sw in range(1, 9):
            routing[sw] = {}
            for subnet, (dst_sw, host_port) in self.HOSTS.items():
                if sw == dst_sw:
                    # This switch is directly connected to the destination host
                    routing[sw][subnet] = host_port
                else:
                    # BFS to find the shortest path (minimum hops) to dst_sw
                    queue = [[sw]]
                    visited = {sw}

                    while queue:
                        path = queue.pop(0)
                        node = path[-1]

                        if node == dst_sw:
                            # Found the shortest path — get the first step
                            next_hop = path[1]
                            # Find the local port on 'sw' that leads to next_hop
                            for u, v, pu, pv in self.LINKS:
                                if u == sw and v == next_hop:
                                    routing[sw][subnet] = pu
                                    break
                                elif v == sw and u == next_hop:
                                    routing[sw][subnet] = pv
                                    break
                            break

                        # Expand neighbors of current node
                        for u, v, pu, pv in self.LINKS:
                            nbr = v if u == node else (u if v == node else None)
                            if nbr and nbr not in visited:
                                visited.add(nbr)
                                queue.append(path + [nbr])

        return routing

    def _print_routing_table(self):
        print("Shortest-path routing table (BFS, hop count):")
        for sw in sorted(self.routing_table):
            entries = ', '.join(
                f"{sub.split('.')[0]}→p{port}"
                for sub, port in self.routing_table[sw].items()
            )
            print(f"  S{sw}: {entries}")

    # =========================================================================
    # Switch connects — install computed shortest-path flow rules
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        # Install one IP rule per subnet using the BFS-computed output port.
        # Priority 10 > default table-miss (priority 0) so IP packets are
        # forwarded by the switch without involving the controller again.
        if dpid in self.routing_table:
            for ip_dst, out_port in self.routing_table[dpid].items():
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=ip_dst
                )
                actions = [parser.OFPActionOutput(out_port)]
                self.program_flow(datapath, match, actions, priority=10)

            print(f"S{dpid}: shortest-path rules installed")

    # =========================================================================
    # Packet-in — ARP on spanning tree only (prevents broadcast loops)
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

        # Forward ARP only on spanning tree ports to avoid broadcast loops
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            tree_ports = self.SPANNING_TREE_PORTS.get(dpid, set())
            for port in tree_ports:
                if port != in_port:
                    self.send_pkt(datapath, msg.data, port)

    # =========================================================================
    # Monitoring — identical to Task 2.1
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

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.current_stats[dpid] = [
            stat for stat in ev.msg.body if stat.priority > 0
        ]
        self.pending_replies -= 1
        if self.pending_replies <= 0:
            self._display_stats()

    def _display_stats(self):
        print('$SDNC_CLEAR_SCREEN$')
        print('=' * 62)
        print('  SHORTEST PATH TRAFFIC MONITOR  —  Task 2.2')
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
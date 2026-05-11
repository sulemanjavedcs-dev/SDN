from controller import CockpitApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub  
import heapq             


class Task23(CockpitApp):

    # -------------------------------------------------------------------------
    LINKS = [
     # (sw_a, sw_b, port_on_a, port_on_b, latency_ms)
     (1, 2, 1, 1,  10),   # s1-s2: 10ms (black)
     (1, 3, 2, 1,  10),   # s1-s3: 10ms (black)  
     (1, 4, 3, 1, 100),   # s1-s4: 100ms (purple)
     (2, 3, 2, 2,  10),   # s2-s3: 10ms (black)
     (2, 5, 3, 1,  10),   # s2-s5: 10ms (black)
     (3, 4, 3, 2,  50),   # s3-s4: 50ms (red)    
     (3, 5, 4, 2,  10),   # s3-s5: 10ms (black)
     (3, 6, 5, 1,  50),   # s3-s6: 50ms (red)
     (4, 6, 3, 2,  50),   # s4-s6: 50ms (red)   
     (4, 8, 4, 1, 100),   # s4-s8: 100ms (purple)
     (5, 6, 3, 3,  10),   # s5-s6: 10ms (black)  
     (5, 7, 4, 1,  50),   # s5-s7: 50ms (red)    
     (6, 7, 4, 2,  10),   # s6-s7: 10ms (black)  
     (6, 8, 5, 2,  50),   # s6-s8: 50ms (red)
     (7, 8, 3, 3,  10),   # s7-s8: 10ms (black)
     ]

    # Host attachment: subnet → (switch_dpid, host_port)
    HOSTS = {
        '11.0.0.0/8': (1, 4),   # H1 on s1 port 4
        '22.0.0.0/8': (4, 5),   # H2 on s4 port 5
        '33.0.0.0/8': (8, 4),   # H3 on s8 port 4
        '44.0.0.0/8': (7, 4),   # H4 on s7 port 4
    }

    # -------------------------------------------------------------------------
    # SPANNING TREE PORTS — loop-free ARP (same fix as Tasks 2.1 and 2.2)
    # Flooding ARP in a mesh causes broadcast storms → ping fails.
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
        super(Task23, self).__init__(*args, **kwargs)
        self.info("Task 2.3 - Latency-Based Routing")

        # Build adjacency: adj[sw][neighbor] = (local_port, latency_ms)
        self.adj = self._build_adjacency()

        # Compute lowest-latency routing table using Dijkstra's algorithm.
        # This differs from Task 2.2 (BFS/hop count) because each link has
        # a different cost — Dijkstra finds the minimum total latency path.
        self.routing_table = self._compute_routing_table()
        self._print_routing_table()

        self.datapaths = {}
        self.current_stats = {}
        self.pending_replies = 0

        hub.spawn(self._monitor_loop)

    # =========================================================================
    # Build adjacency list: adj[sw][neighbor] = (port_to_neighbor, latency)
    # =========================================================================
    def _build_adjacency(self):
        adj = {}
        for u, v, pu, pv, lat in self.LINKS:
            if u not in adj: adj[u] = {}
            if v not in adj: adj[v] = {}
            adj[u][v] = (pu, lat)
            adj[v][u] = (pv, lat)
        return adj

    # =========================================================================
    # Dijkstra's algorithm — finds minimum latency path between two switches
    #
    # Uses a min-heap (heapq) for efficiency.
    # Heap entry: (total_latency_so_far, current_switch)
    # =========================================================================
    def _dijkstra(self, src, dst):
        dist = {src: 0}
        prev = {src: None}
        heap = [(0, src)]

        while heap:
            cost, u = heapq.heappop(heap)
            if cost > dist.get(u, float('inf')):
                continue
            if u == dst:
                break
            for v, (port, lat) in self.adj.get(u, {}).items():
                new_cost = cost + lat
                if new_cost < dist.get(v, float('inf')):
                    dist[v] = new_cost
                    prev[v] = u
                    heapq.heappush(heap, (new_cost, v))

        # Reconstruct path
        path = []
        cur = dst
        while cur is not None:
            path.append(cur)
            cur = prev.get(cur)
        path.reverse()
        return path, dist.get(dst, float('inf'))

    def _compute_routing_table(self):
        routing = {}
        for sw in range(1, 9):
            routing[sw] = {}
            for subnet, (dst_sw, host_port) in self.HOSTS.items():
                if sw == dst_sw:
                    routing[sw][subnet] = host_port
                else:
                    path, _ = self._dijkstra(sw, dst_sw)
                    next_hop = path[1]
                    port, _ = self.adj[sw][next_hop]
                    routing[sw][subnet] = port
        return routing

    def _print_routing_table(self):
        print("Latency-based routing table (Dijkstra):")
        for sw in sorted(self.routing_table):
            entries = ', '.join(
                f"{sub.split('.')[0]}→p{port}"
                for sub, port in self.routing_table[sw].items()
            )
            print(f"  S{sw}: {entries}")

    # =========================================================================
    # Switch connects — install computed lowest-latency flow rules
    # =========================================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        if dpid in self.routing_table:
            for ip_dst, out_port in self.routing_table[dpid].items():
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=ip_dst
                )
                actions = [parser.OFPActionOutput(out_port)]
                self.program_flow(datapath, match, actions, priority=10)
            print(f"S{dpid}: latency-optimal rules installed")

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

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            tree_ports = self.SPANNING_TREE_PORTS.get(dpid, set())
            for port in tree_ports:
                if port != in_port:
                    self.send_pkt(datapath, msg.data, port)

    # =========================================================================
    # Monitoring — identical to Tasks 2.1 and 2.2
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
        print('  LATENCY-BASED ROUTING MONITOR  —  Task 2.3')
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
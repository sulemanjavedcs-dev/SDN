# Basic imports for Ryu
# While some of these are not actually needed for this base class,
# they may be usefull for your controller.
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet, arp, ipv4, ipv6


class CockpitApp(app_manager.RyuApp):
    """
    A base class for ryu controllers written for SDN-Cockpit.
    Provides some convenience methods for common SDN operations.
    Those convenience methods are designed to work with OpenFlow 1.5,
    the protocol version supported by all switches in SDN-Cockpit.
    """

    # RyuApp reads this to know which protocol versions we support.
    OFP_VERSIONS = [ofproto.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CockpitApp, self).__init__(*args, **kwargs)

    def info(self, text):
        """
        Print a short string in a small box.

        Args:
            text: The text to print.
        """
        print("*" * (len(text) + 4))
        print(f"* {text} *")
        print("*" * (len(text) + 4))

    def clear_screen(self):
        print('$SDNC_CLEAR_SCREEN$')

    def program_flow(
            self, datapath, match, actions, priority=0,
            hard_timeout=0, idle_timeout=0):
        """
        Programs a flow to the switch identified by the given datapath.

        Args:
            datapath: Describes an the connection between the controller
                and the OpenFlow switch onto which the new flow will be
                installed.
            match: Packets must match this for the flow rule to be
                applied to them. If another flow with the same exact
                match exists on the switch already, it will be
                overridden.
            actions: List. Describe what the switch should do with
            matching packets. There are many types of actions in the
            OpenFlow specs, for example OFPActionOutput.
            priority (int): Priority level of flow entry.
            idle_timeout (int): Idle time before discarding (seconds).
                A value of 0 (default) means no timeout.
            hard_timeout (int): Max time before discarding (seconds).
                A value of 0 (default) means no timeout.
        """
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )
        ]
        flowmod = parser.OFPFlowMod(
            datapath,
            match=match,
            instructions=instructions,
            priority=priority,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(flowmod)

    def send_pkt(self, datapath, data, port=ofproto.OFPP_FLOOD):
        """
        Send a packet from the controller to a switch where it will be
        emitted into the network.

        Args:
            datapath: Describes an OpenFlow switch to which the packet
                will be sent for emittance.
            data: The packet to emit.
            port: The port on which the packet will be emitted.
        """
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            actions=actions,
            in_port=ofproto.OFPP_CONTROLLER,
            data=data,
            buffer_id=ofproto.OFP_NO_BUFFER)
        datapath.send_msg(out)

    # This decorator makes sure that the function below is invoked
    # every time a new switch is connected to our controller.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def __cockpit_app_switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        print("switch with id {:d} connected".format(datapath.id))

        # Install default flow, which will forward all otherwise
        # unmatched packets to the controller.
        self.program_flow(
            datapath,
            parser.OFPMatch(),  # match on every packet
            [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )],
            hard_timeout=0,  # never delete this flow
            idle_timeout=0  # never delete this flow
        )

        # Prevent truncation of packets
        datapath.send_msg(
            datapath.ofproto_parser.OFPSetConfig(
                datapath,
                datapath.ofproto.OFPC_FRAG_NORMAL,
                0xffff
            )
        )

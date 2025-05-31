
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types

# ----------------------
# Learning Switch (L2)
# ----------------------
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Regola di default: invia tutto al controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignora LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        self.logger.info("Switch %s apprende MAC %s sulla porta %s", dpid, src, in_port)

        out_port = (self.mac_to_port[dpid][dst]
                    if dst in self.mac_to_port[dpid]
                    else ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        # Se conosciamo la porta di uscita, installa flusso L2
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_src=src, eth_dst=dst)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                    match=match, instructions=inst)
            datapath.send_msg(mod)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath,
                                   buffer_id=msg.buffer_id,
                                   in_port=in_port,
                                   actions=actions,
                                   data=data)
        datapath.send_msg(out)

# ----------------------
# Router L3 semplice
# ----------------------
class SimpleRouter13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleRouter13, self).__init__(*args, **kwargs)
        # ARP table: IP -> MAC
        self.arp_table = {}
        # Routing table: prefix -> (nexthop_ip, out_port)
        self.route_table = [
            # Esempio: rete 10.0.0.0/24 via port 1
            ("10.0.0.0", "255.255.255.0", None, 1),
            ("11.0.0.0", "255.255.255.0", None, 2),
        ]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Regola di default: invia tutti i pacchetti al controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Gestione ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
            return

        # Solo IPv4
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        dst_ip = ip_pkt.dst

        # Match routing table
        for (nw, mask, nexthop, port) in self.route_table:
            if self.ip_in_subnet(dst_ip, nw, mask):
                self.forward_ip(datapath, msg, in_port, dst_ip, nexthop, port)
                return

    def handle_arp(self, datapath, port, pkt):
        arp_pkt = pkt.get_protocols(arp.arp)[0]
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        self.arp_table[src_ip] = src_mac
        self.logger.info("ARP: memorizzato %s -> %s", src_ip, src_mac)
        # Qui si possono generare ARP reply se necessario

    def forward_ip(self, datapath, msg, in_port, dst_ip, nexthop, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Se serve risolvere ARP per il next hop
        mac = self.arp_table.get(nexthop or dst_ip)
        if not mac:
            # invia ARP request out_port
            return

        actions = [parser.OFPActionSetField(eth_dst=mac),
                   parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=1,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    @staticmethod
    def ip_in_subnet(ip, network, netmask):
        import socket, struct
        ipaddr = struct.unpack('!I', socket.inet_aton(ip))[0]
        net = struct.unpack('!I', socket.inet_aton(network))[0]
        mask = struct.unpack('!I', socket.inet_aton(netmask))[0]
        return (ipaddr & mask) == (net & mask)


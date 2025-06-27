
import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4

class AdvancedRouterController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AdvancedRouterController, self).__init__(*args, **kwargs)
        
        self.router_dpids = [1, 2, 3, 4]
        self.switch_dpid = 5

        # NUOVI IP PER LA RETE NAT
        nat_ip = '172.16.0.254'
        nat_mac = '00:00:00:00:FF:FF'

        self.interface_definitions = {
            1: {'10.0.0.1/24': 1, '200.0.0.1/30': 2, '170.0.0.1/30': 3},
            2: { # R2 ora ha la nuova rete NAT
                '200.0.0.2/30': 1,
                '192.168.1.1/24': 2,
                '172.16.0.1/24': 3
            },
            3: {'180.1.2.1/30': 1, '11.0.0.1/24': 2},
            4: {'170.0.0.2/30': 1, '180.1.2.2/30': 2, '10.8.1.1/24': 3}
        }
        
        self.router_interfaces = {
            1: {'10.0.0.1':'00:10:00:00:01:01', '200.0.0.1':'00:10:00:00:01:02', '170.0.0.1':'00:10:00:00:01:03'},
            2: {'200.0.0.2':'00:10:00:00:02:01', '192.168.1.1':'00:10:00:00:02:02', '172.16.0.1':'00:10:00:00:02:03'},
            3: {'180.1.2.1':'00:10:00:00:03:01', '11.0.0.1':'00:10:00:00:03:02'},
            4: {'170.0.0.2':'00:10:00:00:04:01', '180.1.2.2':'00:10:00:00:04:02', '10.8.1.1':'00:10:00:00:04:03'}
        }
        
        self.arp_table = {
            '10.0.0.2': '00:00:00:00:00:01', '10.0.0.3': '00:00:00:00:00:02',
            '11.0.0.2': '00:00:00:00:00:03', '192.168.1.2': '00:00:00:00:00:04', '10.8.1.2': '00:00:00:00:00:05',
            '10.0.0.1': '00:10:00:00:01:01', '200.0.0.1': '00:10:00:00:01:02', '170.0.0.1': '00:10:00:00:01:03',
            '200.0.0.2': '00:10:00:00:02:01', '192.168.1.1': '00:10:00:00:02:02', '172.16.0.1': '00:10:00:00:02:03',
            '180.1.2.1': '00:10:00:00:03:01', '11.0.0.1': '00:10:00:00:03:02',
            '170.0.0.2': '00:10:00:00:04:01', '180.1.2.2': '00:10:00:00:04:02', '10.8.1.1': '00:10:00:00:04:03',
            nat_ip: nat_mac
        }

        self.routing_table = {
            1: {
                '10.0.0.0/24': 'direct', '11.0.0.0/24': '170.0.0.2',
                '10.8.1.0/24': '170.0.0.2', '0.0.0.0/0': '200.0.0.2'
            },
            2: {
                '192.168.1.0/24': 'direct',
                '172.16.0.0/24': 'direct', # Rete del NAT
                '10.0.0.0/24': '200.0.0.1', '11.0.0.0/24': '200.0.0.1',
                '10.8.1.0/24': '200.0.0.1', '0.0.0.0/0': nat_ip
            },
            3: {'11.0.0.0/24': 'direct', '0.0.0.0/0': '180.1.2.2'},
            4: {
                '10.8.1.0/24': 'direct', '11.0.0.0/24': '180.1.2.1',
                '0.0.0.0/0': '170.0.0.1'
            }
        }
        
        self.mac_to_port = {}
        self.logger.info("Controller (NAT su R2 con IP 172.16.0.0/24) avviato.")

    # ... (Tutte le altre funzioni da add_flow in poi rimangono IDENTICHE, inclusa la correzione per _handle_l2_switch) ...
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto=datapath.ofproto; parser=datapath.ofproto_parser
        inst=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod=parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        self.logger.info(f"==> Regola Installata (DPID {datapath.id}): Prio={priority}, Match={match}, Actions={actions}")
        datapath.send_msg(mod)
    def _send_packet(self, datapath, port, pkt):
        ofproto=datapath.ofproto; parser=datapath.ofproto_parser
        pkt.serialize(); data=pkt.data
        actions=[parser.OFPActionOutput(port=port)]
        out=parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath=ev.msg.datapath; ofproto=datapath.ofproto; parser=datapath.ofproto_parser
        match=parser.OFPMatch()
        actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Installata regola di table-miss su DPID {datapath.id}")
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg=ev.msg; datapath=msg.datapath; dpid=datapath.id
        in_port=msg.match['in_port']
        pkt=packet.Packet(msg.data)
        eth=pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        if dpid==self.switch_dpid: self._handle_l2_switch(datapath, msg, in_port, eth)
        elif dpid in self.router_dpids: self._handle_l3_router(datapath, msg, in_port, pkt, eth)
    def _handle_l2_switch(self, datapath, msg, in_port, eth):
        dpid=datapath.id; parser=datapath.ofproto_parser; ofproto=datapath.ofproto
        src_mac=eth.src; dst_mac=eth.dst
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions, idle_timeout=60)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out=parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    def _handle_l3_router(self, datapath, msg, in_port, pkt, eth):
        arp_pkt=pkt.get_protocol(arp.arp)
        if arp_pkt: self._handle_arp(datapath, in_port, eth, arp_pkt)
        ipv4_pkt=pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt: self._handle_ipv4(datapath, msg, in_port, eth, ipv4_pkt)
    def _handle_arp(self, datapath, port, eth, arp_pkt):
        dpid=datapath.id
        if dpid not in self.router_interfaces: return
        router_ips = self.router_interfaces[dpid]
        if arp_pkt.dst_ip in router_ips and arp_pkt.opcode == arp.ARP_REQUEST:
            router_mac_for_reply = router_ips[arp_pkt.dst_ip]
            p=packet.Packet()
            p.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=router_mac_for_reply))
            p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=router_mac_for_reply, src_ip=arp_pkt.dst_ip, dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
            self._send_packet(datapath, port, p)
    def _handle_ipv4(self, datapath, msg, in_port, eth, ipv4_pkt):
        parser=datapath.ofproto_parser
        dpid=datapath.id
        dst_ip_addr=ipaddress.ip_address(ipv4_pkt.dst)
        router_routes=self.routing_table.get(dpid)
        if not router_routes:
            self.logger.warning(f"DPID {dpid}: Nessuna tabella di routing definita.")
            return
        best_route=None; best_prefix=-1
        for subnet_str, next_hop_str in router_routes.items():
            network=ipaddress.ip_network(subnet_str)
            if dst_ip_addr in network and network.prefixlen > best_prefix:
                best_prefix=network.prefixlen
                best_route=(network, next_hop_str)
        if not best_route:
            self.logger.warning(f"DPID {dpid}: Nessuna rotta trovata per {dst_ip_addr} nella sua tabella.")
            return
        next_hop_ip_str=best_route[1]
        if next_hop_ip_str == 'direct':
            next_hop_ip_str=ipv4_pkt.dst
        dst_mac=self.arp_table.get(next_hop_ip_str)
        if not dst_mac:
            self.logger.warning(f"DPID {dpid}: MAC non trovato per next-hop {next_hop_ip_str} in ARP table.")
            return
        out_port=None
        router_mac_src=None
        for if_definition, port_num in self.interface_definitions[dpid].items():
            if_obj=ipaddress.ip_interface(if_definition)
            if ipaddress.ip_address(next_hop_ip_str) in if_obj.network:
                out_port=port_num
                router_mac_src=self.router_interfaces[dpid][str(if_obj.ip)]
                break
        if out_port is None or out_port == in_port:
            self.logger.warning(f"DPID {dpid}: Impossibile determinare out_port o rilevato loop. Next-Hop:{next_hop_ip_str}, Out:{out_port}, In:{in_port}")
            return
        actions=[
            parser.OFPActionSetField(eth_src=router_mac_src),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_pkt.dst)
        self.add_flow(datapath, 10, match, actions, idle_timeout=30)
        out=parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
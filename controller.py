# final_controller.py
import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp

class FinalNATController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FinalNATController, self).__init__(*args, **kwargs)
        
        self.nat_router_dpid = 6
        self.nat_public_ip = '172.16.0.254'
        self.server_ip = '192.168.100.10'
        self.server_mac = 'AA:BB:CC:DD:EE:FF'
        self.nat_public_port = 1
        self.nat_internal_port = 2
        
        self.dnat_map = {7001: (self.server_ip, 7001)}
        
        self.router_dpids = [1, 2, 3, 4, self.nat_router_dpid]; self.switch_dpid = 5
        self.interface_definitions = {1: {'10.0.0.1/24': 1, '200.0.0.1/30': 2, '170.0.0.1/30': 3}, 2: {'200.0.0.2/30': 1, '192.168.1.1/24': 2, '172.16.0.1/24': 3}, 3: {'180.1.2.1/30': 1, '11.0.0.1/24': 2}, 4: {'170.0.0.2/30': 1, '180.1.2.2/30': 2, '10.8.1.1/24': 3}, self.nat_router_dpid: {f'{self.nat_public_ip}/24': self.nat_public_port, f'192.168.100.1/24': self.nat_internal_port}}
        self.router_interfaces = {1: {'10.0.0.1':'00:10:00:00:01:01', '200.0.0.1':'00:10:00:00:01:02', '170.0.0.1':'00:10:00:00:01:03'}, 2: {'200.0.0.2':'00:10:00:00:02:01', '192.168.1.1':'00:10:00:00:02:02', '172.16.0.1':'00:10:00:00:02:03'}, 3: {'180.1.2.1':'00:10:00:00:03:01', '11.0.0.1':'00:10:00:00:03:02'}, 4: {'170.0.0.2':'00:10:00:00:04:01', '180.1.2.2':'00:10:00:00:04:02', '10.8.1.1':'00:10:00:00:04:03'}, self.nat_router_dpid: {self.nat_public_ip: '00:00:00:00:FF:FE', '192.168.100.1': '00:00:00:00:FF:FD'}}
        self.arp_table = {'10.0.0.2': '00:00:00:00:00:01', '10.0.0.3': '00:00:00:00:00:02', '11.0.0.2': '00:00:00:00:00:03', '192.168.1.2': '00:00:00:00:00:04', '10.8.1.2': '00:00:00:00:00:05', '10.0.0.1': '00:10:00:00:01:01', '200.0.0.1': '00:10:00:00:01:02', '170.0.0.1': '00:10:00:00:01:03', '200.0.0.2': '00:10:00:00:02:01', '192.168.1.1': '00:10:00:00:02:02', '172.16.0.1': '00:10:00:00:02:03', '180.1.2.1': '00:10:00:00:03:01', '11.0.0.1': '00:10:00:00:03:02', '170.0.0.2': '00:10:00:00:04:01', '180.1.2.2': '00:10:00:00:04:02', '10.8.1.1': '00:10:00:00:04:03', self.nat_public_ip: '00:00:00:00:FF:FE', '192.168.100.1': '00:00:00:00:FF:FD', self.server_ip: self.server_mac, '172.16.0.1': '00:10:00:00:02:03'}
        self.routing_table = {1: {'10.0.0.0/24': 'direct', '11.0.0.0/24': '170.0.0.2', '10.8.1.0/24': '170.0.0.2', '0.0.0.0/0': '200.0.0.2'}, 2: {'192.168.1.0/24': 'direct', '172.16.0.0/24': 'direct', '10.0.0.0/24': '200.0.0.1', '11.0.0.0/24': '200.0.0.1', '10.8.1.0/24': '200.0.0.1', '0.0.0.0/0': self.nat_public_ip }, 3: {'11.0.0.0/24': 'direct', '0.0.0.0/0': '180.1.2.2'}, 4: {'10.8.1.0/24': 'direct', '11.0.0.0/24': '180.1.2.1', '0.0.0.0/0': '170.0.0.1'}, self.nat_router_dpid: {ipaddress.ip_network('192.168.100.0/24'): 'direct', '0.0.0.0/0': '172.16.0.1'}}
        self.mac_to_port = {}
        self.logger.info("Controller Finale per Traceroute avviato.")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=60):
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp, ofp, psr = ev.msg.datapath, ev.msg.datapath.ofproto, ev.msg.datapath.ofproto_parser
        self.add_flow(dp, 0, psr.OFPMatch(), [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)], 0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg, dp, dpid = ev.msg, ev.msg.datapath, ev.msg.datapath.id; pkt = packet.Packet(msg.data); eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        
        in_port = msg.match['in_port']
        if dpid == self.nat_router_dpid: self._handle_nat_router(msg, dp, in_port, pkt, eth)
        elif dpid == self.switch_dpid: self._handle_l2_switch(msg, dp, in_port, eth)
        else: self._handle_l3_router(msg, dp, in_port, pkt, eth)

    def _handle_nat_router(self, msg, datapath, in_port, pkt, eth):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt: self._handle_arp(datapath, in_port, eth, arp_pkt)
            return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        parser = datapath.ofproto_parser
        
        if in_port == self.nat_public_port and ip_pkt.dst == self.nat_public_ip and tcp_pkt and tcp_pkt.dst_port in self.dnat_map:
            target_ip, target_port = self.dnat_map[tcp_pkt.dst_port]
            self.logger.info(f"NAT (FWD): Traduco richiesta per porta {tcp_pkt.dst_port} a {target_ip}:{target_port}")
            
            match_fwd = parser.OFPMatch(in_port=self.nat_public_port, eth_type=eth.ethertype, ip_proto=6, ipv4_src=ip_pkt.src, ipv4_dst=self.nat_public_ip, tcp_dst=tcp_pkt.dst_port)
            actions_fwd = [parser.OFPActionSetField(eth_dst=self.server_mac), parser.OFPActionSetField(ipv4_dst=target_ip), parser.OFPActionSetField(tcp_dst=target_port), parser.OFPActionOutput(self.nat_internal_port)]
            self.add_flow(datapath, 20, match_fwd, actions_fwd)

            match_rev = parser.OFPMatch(in_port=self.nat_internal_port, eth_type=eth.ethertype, ip_proto=6, ipv4_src=target_ip, ipv4_dst=ip_pkt.src, tcp_src=target_port)
            actions_rev = [parser.OFPActionSetField(eth_src=self.router_interfaces[self.nat_router_dpid][self.nat_public_ip]), parser.OFPActionSetField(eth_dst=self.arp_table['172.16.0.1']), parser.OFPActionSetField(ipv4_src=self.nat_public_ip), parser.OFPActionOutput(self.nat_public_port)]
            self.add_flow(datapath, 20, match_rev, actions_rev)
            
            data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            datapath.send_msg(parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions_fwd, data=data))
            return

        self._handle_ipv4(msg, datapath, in_port, eth, ip_pkt)

    def _handle_l2_switch(self, msg, datapath, in_port, eth):
        dpid=datapath.id; parser=datapath.ofproto_parser; ofproto=datapath.ofproto; src_mac=eth.src; dst_mac=eth.dst
        self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD); actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD: self.add_flow(datapath, 1, parser.OFPMatch(in_port=in_port, eth_dst=dst_mac), actions)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))

    def _handle_l3_router(self, msg, datapath, in_port, pkt, eth):
        arp_pkt=pkt.get_protocol(arp.arp)
        if arp_pkt: self._handle_arp(datapath, in_port, eth, arp_pkt)
        ipv4_pkt=pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt: self._handle_ipv4(msg, datapath, in_port, eth, ipv4_pkt)

    def _handle_arp(self, datapath, port, eth, arp_pkt):
        dpid=datapath.id
        if dpid in self.router_interfaces and arp_pkt.dst_ip in self.router_interfaces[dpid] and arp_pkt.opcode == arp.ARP_REQUEST:
            p = packet.Packet(); p.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.router_interfaces[dpid][arp_pkt.dst_ip])); p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.router_interfaces[dpid][arp_pkt.dst_ip], src_ip=arp_pkt.dst_ip, dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
            ofproto, parser = datapath.ofproto, datapath.ofproto_parser; p.serialize()
            datapath.send_msg(parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=[parser.OFPActionOutput(port=port)], data=p.data))

    def _handle_ipv4(self, msg, datapath, in_port, eth, ipv4_pkt):
        # === INIZIO CORREZIONE ===
        ofproto = datapath.ofproto 
        parser = datapath.ofproto_parser
        # === FINE CORREZIONE ===
        
        dpid=datapath.id; dst_ip_addr=ipaddress.ip_address(ipv4_pkt.dst); router_routes=self.routing_table.get(dpid);
        if not router_routes: return
        best_route=None
        try: best_route=max(((net, hop) for net, hop in router_routes.items() if dst_ip_addr in ipaddress.ip_network(net)), key=lambda item: ipaddress.ip_network(item[0]).prefixlen)
        except (ValueError, TypeError): pass
        if not best_route: return
        next_hop_ip_str=best_route[1] if best_route[1] != 'direct' else ipv4_pkt.dst; dst_mac=self.arp_table.get(next_hop_ip_str)
        if not dst_mac: return
        out_port = None
        for if_definition, port_num in self.interface_definitions[dpid].items():
            if_obj=ipaddress.ip_interface(if_definition)
            if ipaddress.ip_address(next_hop_ip_str) in if_obj.network: out_port, router_mac_src = port_num, self.router_interfaces[dpid][str(if_obj.ip)]; break
        if out_port is None or out_port == in_port: return
        actions=[parser.OFPActionSetField(eth_src=router_mac_src), parser.OFPActionSetField(eth_dst=dst_mac), parser.OFPActionOutput(out_port)]; match=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_pkt.dst)
        self.add_flow(datapath, 10, match, actions)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))

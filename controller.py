import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp

class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        
        # --- Parametri NAT ---
        self.nat_router_dpid = 6
        self.nat_public_ip = '172.16.0.254'
        self.server_ip = '192.168.100.10'
        self.server_mac = 'AA:BB:CC:DD:EE:FF'
        self.nat_public_port = 1
        self.nat_internal_port = 2
        
        self.dnat_map = { 7001: (self.server_ip, 7001) }
        
        # --- Identificatori dei Dispositivi ---
        self.router_dpids = [1, 2, 3, 4, self.nat_router_dpid]
        self.switch_dpid = 5
        
        # Associazione: DPID -> { IP/mask: porta }
        self.interface_definitions = {
            1: {
                '10.0.0.1/24': 1,
                '200.0.0.1/30': 2,
                '170.0.0.1/30': 3
            },
            2: {
                '200.0.0.2/30': 1,
                '192.168.1.1/24': 2,
                '172.16.0.1/24': 3
            },
            3: {
                '180.1.2.1/30': 1,
                '11.0.0.1/24': 2
            },
            4: {
                '170.0.0.2/30': 1,
                '180.1.2.2/30': 2,
                '10.8.1.1/24': 3
            },
            self.nat_router_dpid: {
                f'{self.nat_public_ip}/24': self.nat_public_port,
                '192.168.100.1/24': self.nat_internal_port
            }
        }

        # Associazione: DPID -> { IP interfaccia: MAC interfaccia }
        self.router_interfaces = {
            1: {
                '10.0.0.1': '00:10:00:00:01:01',
                '200.0.0.1': '00:10:00:00:01:02',
                '170.0.0.1': '00:10:00:00:01:03'
            },
            2: {
                '200.0.0.2': '00:10:00:00:02:01',
                '192.168.1.1': '00:10:00:00:02:02',
                '172.16.0.1': '00:10:00:00:02:03'
            },
            3: {
                '180.1.2.1': '00:10:00:00:03:01',
                '11.0.0.1': '00:10:00:00:03:02'
            },
            4: {
                '170.0.0.2': '00:10:00:00:04:01',
                '180.1.2.2': '00:10:00:00:04:02',
                '10.8.1.1': '00:10:00:00:04:03'
            },
            self.nat_router_dpid: {
                self.nat_public_ip: '00:00:00:00:FF:FE',
                '192.168.100.1': '00:00:00:00:FF:FD'
            }
        }

        # Tabella ARP statica: { IP: MAC }
        self.arp_table = {
            '10.0.0.2': '00:00:00:00:00:01',
            '10.0.0.3': '00:00:00:00:00:02',
            '11.0.0.2': '00:00:00:00:00:03',
            '192.168.1.2': '00:00:00:00:00:04',
            '10.8.1.2': '00:00:00:00:00:05',
            '10.0.0.1': '00:10:00:00:01:01',
            '200.0.0.1': '00:10:00:00:01:02',
            '170.0.0.1': '00:10:00:00:01:03',
            '200.0.0.2': '00:10:00:00:02:01',
            '192.168.1.1': '00:10:00:00:02:02',
            '172.16.0.1': '00:10:00:00:02:03',
            '180.1.2.1': '00:10:00:00:03:01',
            '11.0.0.1': '00:10:00:00:03:02',
            '170.0.0.2': '00:10:00:00:04:01',
            '180.1.2.2': '00:10:00:00:04:02',
            '10.8.1.1': '00:10:00:00:04:03',
            self.nat_public_ip: '00:00:00:00:FF:FE',
            '192.168.100.1': '00:00:00:00:FF:FD',
            self.server_ip: self.server_mac
        }

        # Tabella di routing: DPID -> { Rete Destinazione: Next Hop }
        self.routing_table = {
            1: {
                '10.0.0.0/24': 'direct',
                '11.0.0.0/24': '170.0.0.2',
                '10.8.1.0/24': '170.0.0.2',
                '0.0.0.0/0': '200.0.0.2'
            },
            2: {
                '192.168.1.0/24': 'direct',
                '172.16.0.0/24': 'direct',
                '10.0.0.0/24': '200.0.0.1',
                '11.0.0.0/24': '200.0.0.1',
                '10.8.1.0/24': '200.0.0.1',
                '0.0.0.0/0': self.nat_public_ip
            },
            3: {
                '11.0.0.0/24': 'direct',
                '0.0.0.0/0': '180.1.2.2'
            },
            4: {
                '10.8.1.0/24': 'direct',
                '11.0.0.0/24': '180.1.2.1',
                '0.0.0.0/0': '170.0.0.1'
            },
            self.nat_router_dpid: {
                ipaddress.ip_network('192.168.100.0/24'): 'direct',
                '0.0.0.0/0': '172.16.0.1'
            }
        }
        
       
        
        self.mac_to_port = {}
        self.logger.info("Controller avviato.")


    def add_flow(self, datapath, priority, match, actions, idle_timeout=60):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(datapath=datapath, 
                                priority=priority, 
                                match=match, 
                                idle_timeout=idle_timeout, 
                                instructions=inst)
        
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions, idle_timeout=0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        in_port = msg.match['in_port']
        
        if dpid == self.nat_router_dpid:
            self._handle_nat_router(msg, datapath, in_port, pkt, eth)
        elif dpid == self.switch_dpid:
            self._handle_l2_switch(msg, datapath, in_port, eth)
        else:
            self._handle_l3_router(msg, datapath, in_port, pkt, eth)

    def _handle_nat_router(self, msg, datapath, in_port, pkt, eth):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if not ip_pkt:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                self._handle_arp(datapath, in_port, eth, arp_pkt)
            return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        parser = datapath.ofproto_parser
        
        is_dnat_candidate = (in_port == self.nat_public_port and 
                             ip_pkt.dst == self.nat_public_ip and 
                             tcp_pkt and tcp_pkt.dst_port in self.dnat_map)

        if is_dnat_candidate:
            target_ip, target_port = self.dnat_map[tcp_pkt.dst_port]
            self.logger.info(f"NAT (FWD): Traduco richiesta per porta {tcp_pkt.dst_port} a {target_ip}:{target_port}")
            
            # Regola per il traffico in avanti (da esterno a interno)
            match_fwd = parser.OFPMatch(in_port=self.nat_public_port, eth_type=eth.ethertype, ip_proto=6, 
                                        ipv4_src=ip_pkt.src, ipv4_dst=self.nat_public_ip, tcp_dst=tcp_pkt.dst_port)
            actions_fwd = [parser.OFPActionSetField(eth_dst=self.server_mac), 
                           parser.OFPActionSetField(ipv4_dst=target_ip), 
                           parser.OFPActionSetField(tcp_dst=target_port), 
                           parser.OFPActionOutput(self.nat_internal_port)]
            self.add_flow(datapath, 20, match_fwd, actions_fwd)

            # Regola per il traffico di ritorno (da interno a esterno)
            match_rev = parser.OFPMatch(in_port=self.nat_internal_port, eth_type=eth.ethertype, ip_proto=6,
                                        ipv4_src=target_ip, ipv4_dst=ip_pkt.src, tcp_src=target_port)
            actions_rev = [parser.OFPActionSetField(eth_src=self.router_interfaces[self.nat_router_dpid][self.nat_public_ip]), 
                           parser.OFPActionSetField(eth_dst=self.arp_table['172.16.0.1']), 
                           parser.OFPActionSetField(ipv4_src=self.nat_public_ip), 
                           parser.OFPActionOutput(self.nat_public_port)]
            self.add_flow(datapath, 20, match_rev, actions_rev)
            
            # Invia il pacchetto corrente usando la nuova regola
            data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions_fwd, data=data)
            datapath.send_msg(out)
            return

        # Se non è un caso di DNAT, gestiscilo come un normale pacchetto IPv4
        self._handle_ipv4(msg, datapath, in_port, eth, ip_pkt)

    def _handle_l2_switch(self, msg, datapath, in_port, eth):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        src_mac = eth.src
        dst_mac = eth.dst

        # Apprende il MAC address sorgente
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Decide la porta di output
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]

        # Installa una flow rule se la destinazione è nota, per evitare futuri packet-in
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions)
        
        # Invia il pacchetto
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_l3_router(self, msg, datapath, in_port, pkt, eth):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(datapath, in_port, eth, arp_pkt)
        
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self._handle_ipv4(msg, datapath, in_port, eth, ipv4_pkt)

    def _handle_arp(self, datapath, port, eth, arp_pkt):
        dpid = datapath.id
        
        # Controlla se è una richiesta ARP per una delle interfacce del router
        is_arp_for_router = (dpid in self.router_interfaces and
                             arp_pkt.dst_ip in self.router_interfaces[dpid] and
                             arp_pkt.opcode == arp.ARP_REQUEST)
        
        if is_arp_for_router:
            # Costruisce la risposta ARP
            reply_src_mac = self.router_interfaces[dpid][arp_pkt.dst_ip]
            p = packet.Packet()
            p.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=reply_src_mac))
            p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, 
                                   src_mac=reply_src_mac, src_ip=arp_pkt.dst_ip,
                                   dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
            p.serialize()
            
            # Invia la risposta ARP
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(port=port)]
            out = parser.OFPPacketOut(datapath=datapath, 
                                      buffer_id=ofproto.OFP_NO_BUFFER, 
                                      in_port=ofproto.OFPP_CONTROLLER, 
                                      actions=actions, data=p.data)
            datapath.send_msg(out)

    def _handle_ipv4(self, msg, datapath, in_port, eth, ipv4_pkt):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        dst_ip_addr = ipaddress.ip_address(ipv4_pkt.dst)
        
        # Cerca la rotta nella tabella di routing
        router_routes = self.routing_table.get(dpid)
        if not router_routes:
            return

        # Trova la rotta più specifica (longest prefix match)
        best_route = None
        try:
            matching_routes = []
            for net, hop in router_routes.items():
                if dst_ip_addr in ipaddress.ip_network(net):
                    matching_routes.append((net, hop))
            
            if matching_routes:
                best_route = max(matching_routes, key=lambda item: ipaddress.ip_network(item[0]).prefixlen)
        except (ValueError, TypeError):
            pass  # Ignora errori se la rete non è valida
            
        if not best_route:
            return # Nessuna rotta trovata

        # Determina il next hop e il suo MAC address
        route_net, next_hop_ip_str = best_route
        if next_hop_ip_str == 'direct':
            next_hop_ip_str = ipv4_pkt.dst
        
        dst_mac = self.arp_table.get(str(next_hop_ip_str))
        if not dst_mac:
            return # MAC del next hop non noto

        # Determina la porta di uscita e il MAC sorgente dell'interfaccia
        out_port = None
        router_mac_src = None
        for if_definition, port_num in self.interface_definitions[dpid].items():
            if_obj = ipaddress.ip_interface(if_definition)
            if ipaddress.ip_address(next_hop_ip_str) in if_obj.network:
                out_port = port_num
                router_mac_src = self.router_interfaces[dpid][str(if_obj.ip)]
                break

        if out_port is None or out_port == in_port:
            return # Porta di uscita non trovata o è la stessa di ingresso
        
        # Costruisce le azioni e il match per la flow rule
        actions = [
            parser.OFPActionSetField(eth_src=router_mac_src),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_pkt.dst)
        
        # Installa la flow rule
        self.add_flow(datapath, 10, match, actions)
        
        # Invia il pacchetto corrente
        data = msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, 
                                  buffer_id=msg.buffer_id, 
                                  in_port=in_port, 
                                  actions=actions, data=data)
        datapath.send_msg(out)
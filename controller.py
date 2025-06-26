# advanced_controller.py (versione corretta)
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

        # 1. INTERFACCE (rimane uguale)
        self.router_interfaces = {
            1: {'10.0.0.1':'00:10:00:00:01:01', '200.0.0.1':'00:10:00:00:01:02', '170.0.0.1':'00:10:00:00:01:03'},
            2: {'200.0.0.2':'00:10:00:00:02:01', '192.168.1.1':'00:10:00:00:02:02'},
            3: {'180.1.2.1':'00:10:00:00:03:01', '11.0.0.1':'00:10:00:00:03:02'},
            4: {'170.0.0.2':'00:10:00:00:04:01', '180.1.2.2':'00:10:00:00:04:02', '10.8.1.1':'00:10:00:00:04:03'}
        }
        
        # 2. ASSOCIAZIONE IP -> PORTA (nuova struttura dati per semplicità)
        # {dpid: {ip_addr: port_no}}
        self.ip_to_port = {
            1: {'10.0.0.1': 1, '200.0.0.1': 2, '170.0.0.1': 3},
            2: {'200.0.0.2': 1, '192.168.1.1': 2},
            3: {'180.1.2.1': 1, '11.0.0.1': 2},
            4: {'170.0.0.2': 1, '180.1.2.2': 2, '10.8.1.1': 3}
        }
        
        # 3. TABELLA ARP GLOBALE (rimane uguale)
        self.arp_table = {
            '10.0.0.2': '00:00:00:00:00:01', '10.0.0.3': '00:00:00:00:00:02',
            '11.0.0.2': '00:00:00:00:00:03', '192.168.1.2': '00:00:00:00:00:04', '10.8.1.2': '00:00:00:00:00:05',
            '10.0.0.1': '00:10:00:00:01:01', '200.0.0.1': '00:10:00:00:01:02', '170.0.0.1': '00:10:00:00:01:03',
            '200.0.0.2': '00:10:00:00:02:01', '192.168.1.1': '00:10:00:00:02:02',
            '180.1.2.1': '00:10:00:00:03:01', '11.0.0.1': '00:10:00:00:03:02',
            '170.0.0.2': '00:10:00:00:04:01', '180.1.2.2': '00:10:00:00:04:02', '10.8.1.1': '00:10:00:00:04:03'
        }

        # 4. TABELLA DI ROUTING PER-ROUTER (La grande modifica!)
        # {dpid: {'dest_subnet': 'next_hop_ip'}}
        # 'direct' significa che la rete è direttamente connessa.
        self.routing_table = {
            1: { # Rotte per R1
                '10.0.0.0/24': 'direct',
                '192.168.1.0/24': '200.0.0.2',
                '11.0.0.0/24': '170.0.0.2',
                '10.8.1.0/24': '170.0.0.2'
            },
            2: { # Rotte per R2
                '192.168.1.0/24': 'direct',
                '0.0.0.0/0': '200.0.0.1' # Rotta di default verso R1
            },
            3: { # Rotte per R3
                '11.0.0.0/24': 'direct',
                '0.0.0.0/0': '180.1.2.2' # Rotta di default verso R4
            },
            4: { # Rotte per R4
                '10.8.1.0/24': 'direct',
                '11.0.0.0/24': '180.1.2.1',
                '10.0.0.0/24': '170.0.0.1',
                '192.168.1.0/24': '170.0.0.1'
            }
        }
        
        self.mac_to_port = {}
        self.logger.info("Controller Avanzato (Corretto) avviato.")

    # (Le funzioni add_flow, _send_packet, _switch_features_handler, _packet_in_handler, _handle_l2_switch, _handle_arp non cambiano)
    # ... Incolla qui le funzioni che non cambiano dal codice precedente ...
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
        out=parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
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

    # ====================================================================
    # === LOGICA DI ROUTING _handle_ipv4 COMPLETAMENTE RISCRITTA ========
    # ====================================================================
    def _handle_ipv4(self, datapath, msg, in_port, eth, ipv4_pkt):
        parser = datapath.ofproto_parser
        dpid = datapath.id
        dst_ip_addr = ipaddress.ip_address(ipv4_pkt.dst)

        # 1. Ottieni la tabella di routing specifica per questo router
        router_routes = self.routing_table.get(dpid)
        if not router_routes:
            self.logger.warning(f"DPID {dpid}: Nessuna tabella di routing definita.")
            return

        # 2. Trova la rotta migliore (Longest-prefix match)
        best_route = None
        best_prefix = -1
        for subnet_str, next_hop_str in router_routes.items():
            network = ipaddress.ip_network(subnet_str)
            if dst_ip_addr in network and network.prefixlen > best_prefix:
                best_prefix = network.prefixlen
                best_route = (network, next_hop_str)
        
        if not best_route:
            self.logger.warning(f"DPID {dpid}: Nessuna rotta trovata per {dst_ip_addr} nella sua tabella.")
            return

        # 3. Determina il prossimo hop e il suo MAC
        next_hop_ip_str = best_route[1]
        if next_hop_ip_str == 'direct':
            next_hop_ip_str = ipv4_pkt.dst # Il prossimo hop è la destinazione finale

        dst_mac = self.arp_table.get(next_hop_ip_str)
        if not dst_mac:
            self.logger.warning(f"DPID {dpid}: MAC non trovato per next-hop {next_hop_ip_str} in ARP table.")
            return

        # 4. Determina la porta di uscita e il MAC sorgente del router
        out_port = None
        router_mac_src = None
        
        # Cerca tra le interfacce di questo router quella che può raggiungere il next_hop
        for if_ip_str, port_num in self.ip_to_port[dpid].items():
            if_ip = ipaddress.ip_interface(f"{if_ip_str}/24") # Assumiamo /24 o /30
            # Controllo per reti punto-punto /30
            if ipaddress.ip_network(if_ip_str).max_prefixlen == 32 and if_ip.network.prefixlen < 31:
                 if_ip = ipaddress.ip_interface(f"{if_ip_str}/30")

            if ipaddress.ip_address(next_hop_ip_str) in if_ip.network:
                out_port = port_num
                router_mac_src = self.router_interfaces[dpid][if_ip_str]
                break

        if out_port is None or out_port == in_port:
            self.logger.warning(f"DPID {dpid}: Impossibile determinare out_port o rilevato loop. Next-Hop:{next_hop_ip_str}, Out:{out_port}, In:{in_port}")
            return
            
        # 5. Crea azioni, installa la regola e invia il pacchetto
        actions = [
            parser.OFPActionSetField(eth_src=router_mac_src),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_pkt.dst)
        self.add_flow(datapath, 10, match, actions, idle_timeout=30)
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
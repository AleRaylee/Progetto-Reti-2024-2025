from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time

class Topology(Topo):
    def build(self):
        
        info('*** Aggiunta dei router\n')
        r1 = self.addSwitch('r1', dpid='0000000000000001')
        r2 = self.addSwitch('r2', dpid='0000000000000002')
        r3 = self.addSwitch('r3', dpid='0000000000000003')
        r4 = self.addSwitch('r4', dpid='0000000000000004')
        
        info('*** Aggiunta degli host\n')
        # Aggiunta degli host con IP, MAC e Default Gateway (verso il router locale)
        h1 = self.addHost('h1', ip = '10.0.0.2/24', defaultRoute = "via 10.0.0.1")
        h2 = self.addHost('h2', ip = '10.0.0.3/24', defaultRoute = "via 10.0.0.1")
        h3 = self.addHost('h3', ip = '11.0.0.2/24', defaultRoute = "via 11.0.0.1")
        h4 = self.addHost('h4', ip = '192.168.1.2/24', defaultRoute = "via 192.168.1.1")
        h5 = self.addHost('h5', ip = '10.8.1.2/24', defaultRoute = "via 10.8.1.1")
        
        # Link router-router
        # Links tra i Router (R1, R2, R3, R4)
        self.addLink(r1, r2, bw=1, delay="2ms") # r1-eth2 <-> r2-eth1 (200.0.0.0/30)
        self.addLink(r1, r4, bw=5, delay="2ms") # r1-eth3 <-> r4-eth1 (170.0.0.0/30)
        self.addLink(r3, r4, bw=20, delay="2ms") # r3-eth1 <-> r4-eth2 (180.1.2.0/30)
        
        # Links tra Router e Host Locali
        self.addLink(r2, h4, bw=100, delay ="2ms") # r2-eth2 <-> h4 (192.168.1.0/24)
        self.addLink(r3, h3, bw=1, delay="0.5ms") # r3-eth2 <-> h3 (11.0.0.0/24)
        self.addLink(r4, h5, bw=100, delay="0.05ms") # r4-eth3 <-> h5 (10.8.1.0/24)
        self.addLink(r1,h1)
        self.addLink(r1,h2)
        
        

def run():
    net = Mininet(topo=Topology(), controller=None, link=TCLink, autoSetMacs=True)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    
    info('*** Starting network\n')
    net.start()
    
    # OpenFlow13 su tutti i switch
    for sw in ['r1', 'r2', 'r3','r4']:
        net.get(sw).cmd("ovs-vsctl set Bridge {} protocols=OpenFlow13".format(sw))
    
    info('*** Waiting for controller REST API...\n')
    time.sleep(5)
    
    info('*** Configuring router IPs via REST\n')
    cmds = [
        # IP delle reti locali dei router
        ('0000000000000001', '{"address":"10.0.0.1/24"}'),      # r1 rete locale
        ('0000000000000002', '{"address":"192.168.1.1/24"}'),   # r2 rete locale
        ('0000000000000003', '{"address":"11.0.0.1/24"}'),      # r3 rete locale
        ('0000000000000004', '{"address":"10.8.1.1/24"}'),      # r4 rete locale
        
        # IP dei link inter-router (CORRETTI)
        ('0000000000000001', '{"address":"200.0.0.1/30"}'),     # r1-r2 link
        ('0000000000000002', '{"address":"200.0.0.2/30"}'),     # r2-r1 link
        ('0000000000000001', '{"address":"170.0.0.1/30"}'),     # r1-r4 link
        ('0000000000000004', '{"address":"170.0.0.2/30"}'),     # r4-r1 link
        ('0000000000000003', '{"address":"180.1.2.1/30"}'),     # r3-r4 link                                   
        ('0000000000000004', '{"address":"180.1.2.2/30"}'),     # r4-r3 link (CORRETTO!)
    ]
    
    for dpid, data in cmds:
        curl_cmd = f"curl -s -X POST -d '{data}' http://localhost:8080/router/{dpid}"
        info(f"Executing: {curl_cmd}\n")
        result = c0.cmd(curl_cmd)
        info(f"Result: {result}\n")
        time.sleep(0.5)
    
    info('*** Configuring static routes via REST\n')
    routes = [
        # Rotte da R1 (10.0.0.0/24)
        ('0000000000000001', '{"destination":"192.168.1.0/24","gateway":"200.0.0.2"}'),   # h4 via r2
        ('0000000000000001', '{"destination":"10.8.1.0/24","gateway":"170.0.0.2"}'),      # h5 via r4
        ('0000000000000001', '{"destination":"11.0.0.0/24","gateway":"170.0.0.2"}'),      # h3 via r4->r3
        
        # Rotte da R2 (192.168.1.0/24)
        ('0000000000000002', '{"destination":"10.0.0.0/24","gateway":"200.0.0.1"}'),      # h1,h2 via r1
        ('0000000000000002', '{"destination":"10.8.1.0/24","gateway":"200.0.0.1"}'),      # h5 via r1->r4
        ('0000000000000002', '{"destination":"11.0.0.0/24","gateway":"200.0.0.1"}'),      # h3 via r1->r4->r3
        
        # Rotte da R3 (11.0.0.0/24)
        ('0000000000000003', '{"destination":"10.0.0.0/24","gateway":"180.1.2.2"}'),      # h1,h2 via r4->r1
        ('0000000000000003', '{"destination":"192.168.1.0/24","gateway":"180.1.2.2"}'),   # h4 via r4->r1->r2
        ('0000000000000003', '{"destination":"10.8.1.0/24","gateway":"180.1.2.2"}'),      # h5 via r4
        
        # Rotte da R4 (10.8.1.0/24)
        ('0000000000000004', '{"destination":"10.0.0.0/24","gateway":"170.0.0.1"}'),      # h1,h2 via r1
        ('0000000000000004', '{"destination":"192.168.1.0/24","gateway":"170.0.0.1"}'),   # h4 via r1->r2
        ('0000000000000004', '{"destination":"11.0.0.0/24","gateway":"180.1.2.1"}'),      # h3 via r3
    ]
    
    for dpid, data in routes:
        curl_cmd = f"curl -s -X POST -d '{data}' http://localhost:8080/router/{dpid}"
        info(f"Executing: {curl_cmd}\n")
        result = c0.cmd(curl_cmd)
        info(f"Result: {data}\n")
        time.sleep(0.5)
    
    
    info('*** Running CLI\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
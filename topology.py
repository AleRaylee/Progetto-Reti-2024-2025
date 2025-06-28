



from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    net = Mininet(
        controller=None,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False
    )

    info('*** Aggiunta del controller remoto\n')
    c0 = net.addController(name='c0', controller=RemoteController, ip='127.0.0.1', port=6653, protocols='OpenFlow13')

    info('*** Aggiunta dei dispositivi di rete\n')
    r1 = net.addSwitch('r1', dpid='0000000000000001')
    r2 = net.addSwitch('r2', dpid='0000000000000002')
    r3 = net.addSwitch('r3', dpid='0000000000000003')
    r4 = net.addSwitch('r4', dpid='0000000000000004')
    s1 = net.addSwitch('s1', dpid='0000000000000005')

    info('*** Aggiunta degli host\n')
    h1 = net.addHost('h1', ip='10.0.0.2/24', mac='00:00:00:00:00:01', defaultRoute="via 10.0.0.1")
    h2 = net.addHost('h2', ip='10.0.0.3/24', mac='00:00:00:00:00:02', defaultRoute="via 10.0.0.1")
    h3 = net.addHost('h3', ip='11.0.0.2/24', mac='00:00:00:00:00:03', defaultRoute="via 11.0.0.1")
    h4 = net.addHost('h4', ip='192.168.1.2/24', mac='00:00:00:00:00:04', defaultRoute="via 192.168.1.1")
    h5 = net.addHost('h5', ip='10.8.1.2/24', mac='00:00:00:00:00:05', defaultRoute="via 10.8.1.1")

    info('*** Aggiunta del Router NAT (gestito da Ryu) e del Server\n')
    nat_router = net.addSwitch('nat_router', dpid='0000000000000006')
    server = net.addHost('server', ip='192.168.100.10/24', mac='AA:BB:CC:DD:EE:FF', defaultRoute="via 192.168.100.1")
    
    info('*** Creazione dei collegamenti interni (rispettando le porte del controller)\n')
    # Link tra i dispositivi della nostra rete gestita da Ryu
    net.addLink(r1, s1, port1=1, port2=1, bw=1000, delay="0.05ms")
    net.addLink(r1, r2, port1=2, port2=1, bw=1,  delay="2ms")
    net.addLink(r1, r4, port1=3, port2=1, bw=5,  delay="2ms")
    net.addLink(r3, r4, port1=1, port2=2, bw=20,  delay="2ms")
    net.addLink(r2, h4, port1=2, port2=1, bw=100, delay="0.05ms")
    net.addLink(r3, h3, port1=2, port2=1, bw=1,  delay = "0.5ms")
    net.addLink(r4, h5, port1=3, port2=1, bw=100, delay = "0.05ms")
    net.addLink(s1, h1, port1=2, port2=1 ,bw=54, delay="0.05ms")
    net.addLink(s1, h2, port1=3, port2=1 ,bw=54, delay="0.05ms" )
    net.addLink(r2, nat_router, port1=3, port2=1)
    net.addLink(nat_router, server, port1=2)

   
    info('*** Aggiunta e collegamento del nodo NAT di Mininet (inerte)\n')
    # Aggiungiamo il NAT solo dopo che tutti i nostri link sono stati creati
    nat0 = net.addNAT(name='nat0', inNamespace=False)
    net.addLink(r2, nat0, port1=4)
   
    info('*** Avvio della rete\n')
    net.build()
    c0.start()
    all_switches = [s1, r1, r2, r3, r4, nat_router]
    for sw in all_switches:
        sw.start([c0])
    
    for sw in all_switches:
        sw.cmd(f'ovs-vsctl set Bridge {sw.name} protocols=OpenFlow13')
        
    info('*** Esecuzione della CLI di Mininet\n')
    CLI(net)

    info('*** Arresto della rete\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
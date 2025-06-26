#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_complex_topology():
    net = Mininet(
        controller=None,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False # Disattivato per avere pieno controllo
    )

    info('*** Aggiunta del controller remoto\n')
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653,
        protocols='OpenFlow13'
    )

    info('*** Aggiunta dei dispositivi di rete\n')
    r1 = net.addSwitch('r1', dpid='0000000000000001')
    r2 = net.addSwitch('r2', dpid='0000000000000002')
    r3 = net.addSwitch('r3', dpid='0000000000000003')
    r4 = net.addSwitch('r4', dpid='0000000000000004')
    s1 = net.addSwitch('s1', dpid='0000000000000005')

    info('*** Aggiunta degli host\n')
    # Nota: I MAC sono inventati ma coerenti con la configurazione del controller
    h1 = net.addHost('h1', ip='10.0.0.2/24', mac='00:00:00:00:00:01', defaultRoute="via 10.0.0.1")
    h2 = net.addHost('h2', ip='10.0.0.3/24', mac='00:00:00:00:00:02', defaultRoute="via 10.0.0.1")
    h3 = net.addHost('h3', ip='11.0.0.2/24', mac='00:00:00:00:00:03', defaultRoute="via 11.0.0.1")
    h4 = net.addHost('h4', ip='192.168.1.2/24', mac='00:00:00:00:00:04', defaultRoute="via 192.168.1.1")
    h5 = net.addHost('h5', ip='10.8.1.2/24', mac='00:00:00:00:00:05', defaultRoute="via 10.8.1.1")

    info('*** Creazione dei collegamenti (con porte definite)\n')
    # --- Collegamenti di R1 (DPID 1) ---
    net.addLink(r1, s1, port1=1, port2=1) # Verso la rete 10.0.0.0/24
    net.addLink(r1, r2, port1=2, port2=1) # Verso R2 (rete 200.0.0.0/30)
    net.addLink(r1, r4, port1=3, port2=1) # Verso R4 (rete 170.0.0.0/30)

    # --- Collegamenti di R2 (DPID 2) ---
    # porta 1 già usata per R1
    net.addLink(r2, h4, port1=2, port2=1) # Verso H4 (rete 192.168.1.0/24)

    # --- Collegamenti di R3 (DPID 3) ---
    net.addLink(r3, r4, port1=1, port2=2) # Verso R4 (rete 180.1.2.0/30)
    net.addLink(r3, h3, port1=2, port2=1) # Verso H3 (rete 11.0.0.0/24)

    # --- Collegamenti di R4 (DPID 4) ---
    # porta 1 già usata per R1
    # porta 2 già usata per R3
    net.addLink(r4, h5, port1=3, port2=1) # Verso H5 (rete 10.8.1.0/24)
    
    # --- Collegamenti dello Switch S1 ---
    # porta 1 già usata per R1
    net.addLink(s1, h1, port1=2, port2=1)
    net.addLink(s1, h2, port1=3, port2=1)
    
    info('*** Avvio della rete\n')
    net.build()
    c0.start()
    s1.start([c0]); r1.start([c0]); r2.start([c0]); r3.start([c0]); r4.start([c0])

    info('*** Impostazione della versione di OpenFlow a 1.3\n')
    for sw in [s1, r1, r2, r3, r4]:
        sw.cmd(f'ovs-vsctl set Bridge {sw.name} protocols=OpenFlow13')

    info('*** Esecuzione della CLI di Mininet\n')
    CLI(net)

    info('*** Arresto della rete\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_complex_topology()
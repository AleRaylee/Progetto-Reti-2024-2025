from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import Controller, RemoteController, OVSSwitch

def create_topo():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)

    # Host
    h1 = net.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
    h2 = net.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
    h3 = net.addHost('h3', ip='11.0.0.1/24', defaultRoute='via 11.0.0.254')
    h4 = net.addHost('h4', ip='192.168.1.1/24', defaultRoute='via 192.168.1.254')
    h5 = net.addHost('h5', ip='10.8.1.1/24', defaultRoute='via 10.8.1.254')

    # Router
    r1 = net.addHost('r1',cls = OVSSwitch)
    r2 = net.addHost('r2',cls = OVSSwitch)
    r3 = net.addHost('r3',cls = OVSSwitch)
    r4 = net.addHost('r4',cls = OVSSwitch)

    # Switch
    s1 = net.addSwitch('s1')

    # NAT
    nat = net.addNAT(name='nat', ip='8.8.8.8/24')

    # Controller
    '''
        IP_CONTROLLER = '127.0.0.1'      # se Ryu gira sulla stessa macchina
        PORT_CONTROLLER = 6633  oppure 6653
    '''
    controller = net.addController(
        name='controller',
        controller=RemoteController,
        ip='127.0.0.1',     # <-- sostituisci con IP reale
        port=6633    # <-- sostituisci con porta reale
    )

    # Link
    net.addLink(h1, s1, cls=TCLink, bw=54, delay='0.05ms')
    net.addLink(h2, s1, cls=TCLink, bw=54, delay='0.05ms')
    net.addLink(s1, r1, cls=TCLink, bw=1000, delay='0.05ms')
    net.addLink(h3, r3, cls=TCLink, bw=1, delay='0.5ms')
    net.addLink(h4, r2, cls=TCLink, bw=100, delay='0.05ms')
    net.addLink(h5, r4, cls=TCLink, bw=100, delay='0.05ms')
    net.addLink(r1, r2, cls=TCLink, bw=1, delay='2ms')
    net.addLink(r1, r4, cls=TCLink, bw=5, delay='2ms')
    net.addLink(r3, r4, cls=TCLink, bw=20, delay='2ms')
    net.addLink(r2, nat, cls=TCLink, bw=10, delay='2ms')

    net.build()
    controller.start()
    for r in (r1, r2, r3, r4):
        # abilita forwarding IPv4
        r.cmd('sysctl -w net.ipv4.ip_forward=1')
    s1.start([controller])
    r1.start([controller])
    r2.start([controller])
    r3.start([controller])
    r4.start([controller])
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topo()


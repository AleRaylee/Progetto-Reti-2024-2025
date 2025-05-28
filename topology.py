from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import Controller,NAT,RemoteController,OVSKernelSwitch,UserSwitch,OVSSwitch

def create_topo():

    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)

     #Aggiungiamo gli Host
    h1 = net.addHost('h1', ip = '10.0.0.1/24', defaultRoute = 'via 10.0.0.254')
    h2 = net.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
    h3 = net.addHost('h3', ip='11.0.0.1/24', defaultRoute='via 11.0.0.254')
    h4 = net.addHost('h4', ip='192.168.1.1/24', defaultRoute='via 192.168.1.254')
    h5 = net.addHost('h5', ip='10.8.1.1/24', defaultRoute='via 10.8.1.254')

    #Aggiungi router
    r1 = net.addSwitch('r1')
    r2 = net.addSwitch('r2')
    r3 = net.addSwitch('r3')
    r4 = net.addSwitch('r4')

    '''  
    Se mi dovesse dare problemi
    r1 = net.addSwitch('r1', cls=OVSSwitch)  # Meglio specificare OVSSwitch
    r2 = net.addSwitch('r2', cls=OVSSwitch)
    r3 = net.addSwitch('r3', cls=OVSSwitch)
    r4 = net.addSwitch('r4', cls=OVSSwitch)
    
    '''

    #Aggiungiamo lo Switch
    s1 = net.addSwitch('s1')

    #Aggiungiamo il nodo NAT
    # R1-R2
    nat = net.addNode('nat', csl = NAT ,ip ='10.255.255.2/30')

    #Aggiungiamo il controller
    #IP_CONTROLLER sara l'ip del controller RYU
    #PORT_CONTROLLER sara la porta del controller RYU
    controller = net.addController(
        name = 'controller',
        controller = RemoteController,
        ip = IP_CONTROLLER,
        port = PORT_CONTROLLER
    )

    #Aggiungiamo le connessioni:
    #Rete 10.0.0.0/24
    net.addLink(h1, s1, cls = TCLink, bw=54, delay='0.05ms')
    net.addLink(h2, s1, cls = TCLink, bw=54, delay='0.05ms')
    #S1-R1
    net.addLink(s1, r1, cls = TCLink, bw=1000, delay='0.05ms')

    #R3-H3
    net.addLink(h3,r3,cls = TCLink,bw=1,delay='0.5ms')
    #H4-R2
    net.addLink(h4,r2, cls = TCLink,bw=100, delay='0.05ms')
    #H5-R4
    net.addLink(h5, r4,cls = TCLink,bw=100, delay='0.05ms')

    #Collegamenti fra router
    #R1-R2
    net.addLink(r1, r2, cls=TCLink, bw=1, delay='2ms')
    #R1-R4
    net.addLink(r1, r4, cls=TCLink, bw=5, delay='2ms')
    #R3-R4
    net.addLink(r3, r4, cls=TCLink, bw=20, delay='2ms')
    #R2-NAT
    net.addLink(r2,nat,cls=TCLink,bw=10,delay='2ms')

    net.build()
    controller.start()

    s1.start([controller])
    r1.start([controller])
    r2.start([controller])
    r3.start([controller])
    r4.start([controller])

    if __name__ == '__main__':
        setLogLevel('info')
        create_topo()


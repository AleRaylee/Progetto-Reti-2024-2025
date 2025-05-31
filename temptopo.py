#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LinuxRouter( Node ):
    """A Node with IP forwarding enabled."""
    def config( self, **params ):
        super( LinuxRouter, self ).config( **params )
        # Enable forwarding
        self.cmd( 'sysctl -w net.ipv4.ip_forward=1' )
    def terminate( self ):
        self.cmd( 'sysctl -w net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()

def build():
    net = Mininet( switch=OVSSwitch, link=TCLink, autoSetMacs=True )
    info( '*** Adding routers\n' )
    r1 = net.addHost( 'r1', cls=LinuxRouter, ip='10.0.0.1/24' )
    r2 = net.addHost( 'r2', cls=LinuxRouter )
    r3 = net.addHost( 'r3', cls=LinuxRouter )
    r4 = net.addHost( 'r4', cls=LinuxRouter )

    info( '*** Adding switch for subnet 10.0.0.0/24\n' )
    s1 = net.addSwitch( 's1' )

    info( '*** Adding hosts\n' )
    # Subnet 10.0.0.0/24
    h1 = net.addHost( 'h1', ip='10.0.0.101/24', defaultRoute='via 10.0.0.1' )
    h2 = net.addHost( 'h2', ip='10.0.0.102/24', defaultRoute='via 10.0.0.1' )
    # Subnet 11.0.0.0/24
    h3 = net.addHost( 'h3', ip='11.0.0.3/24', defaultRoute='via 11.0.0.1' )
    # Subnet 192.168.1.0/24
    h4 = net.addHost( 'h4', ip='192.168.1.4/24', defaultRoute='via 192.168.1.1' )
    # Subnet 10.8.1.0/24
    h5 = net.addHost( 'h5', ip='10.8.1.5/24', defaultRoute='via 10.8.1.1' )
    # “Internet” Server Flask behind NAT
    server = net.addHost( 'server', ip='8.8.8.8/24', defaultRoute='via 8.8.8.1' )

    info( '*** Creating links\n' )
    # h1–s1, h2–s1
    net.addLink( h1, s1, bw=54, delay='0.05ms' )
    net.addLink( h2, s1, bw=54, delay='0.05ms' )
    # s1–r1
    net.addLink( s1, r1, bw=1000, delay='0.05ms',
                 intfName2='r1-eth0', params2={ 'ip':'10.0.0.1/24' } )

    # r1–r2 (200.0.0.0/30)
    net.addLink( r1, r2, bw=1, delay='2ms',
                 intfName1='r1-eth1', params1={ 'ip':'200.0.0.1/30' },
                 intfName2='r2-eth0', params2={ 'ip':'200.0.0.2/30' } )

    # r3–h3 (11.0.0.0/24)
    net.addLink( h3, r3, bw=1, delay='0.5ms',
                 intfName2='r3-eth0', params2={ 'ip':'11.0.0.1/24' } )

    # r3–r4 (180.1.2.0/30)
    net.addLink( r3, r4, bw=20, delay='2ms',
                 intfName1='r3-eth1', params1={ 'ip':'180.1.2.1/30' },
                 intfName2='r4-eth0', params2={ 'ip':'180.1.2.2/30' } 
                )

    # r4–h5 (10.8.1.0/24)
    net.addLink( r4, h5, bw=100, delay='0.05ms',
                 intfName1='r4-eth1', params1={ 'ip':'10.8.1.1/24' } )

    # r1–r4 “back‐up” (170.0.0.0/30)
    net.addLink( r1, r4, bw=5, delay='2ms',
                 intfName1='r1-eth2', params1={ 'ip':'170.0.0.1/30' },
                 intfName2='r4-eth2', params2={ 'ip':'170.0.0.2/30' } )

    # r2–h4 (192.168.1.0/24)
    net.addLink( r2, h4, bw=100, delay='0.05ms',
                 intfName1='r2-eth1', params1={ 'ip':'192.168.1.1/24' } )

    # r2–server (NAT) on 8.8.8.0/24
    net.addLink( r2, server,
                 intfName1='r2-eth2', params1={ 'ip':'8.8.8.1/24' } )

    info( '*** Starting network\n' )
    net.build()

    # Enable NAT on r2: masquerade all internal subnets to 8.8.8.1
    info( '*** Configuring NAT on r2\n' )
    r2.cmd( 'iptables -t nat -A POSTROUTING -o r2-eth2 -j MASQUERADE' )
    r2.cmd( 'sysctl -w net.ipv4.ip_forward=1' )

    # Static routes on routers for all subnets
    info( '*** Adding static routes\n' )
    # r1 knows 11.0.0.0/24 via r3
    r1.cmd( 'ip route add 11.0.0.0/24 via 180.1.2.1 dev r1-eth2' )
    # r1 knows 192.168.1.0/24 via r2
    # already connected via r1-eth1
    # r1 knows 10.8.1.0/24 via r4
    r1.cmd('ip route add 180.1.2.0/30 via 170.0.0.2 dev r1-eth2')

    # r2 routes to 10.0.0.0/24 and 11.0.0.0/24 via 200.0.0.1
    r2.cmd( 'ip route add 10.0.0.0/24 via 200.0.0.1 dev r2-eth0' )
    r2.cmd( 'ip route add 11.0.0.0/24 via 200.0.0.1 dev r2-eth0' )
    # r2 to 10.8.1.0/24 via 200.0.0.1 -> r1 -> r4 path
    r2.cmd( 'ip route add 10.8.1.0/24 via 200.0.0.1 dev r2-eth0' )

    # r3 routes to 10.0.0.0/24 and 192.168.1.0/24 via 180.1.2.2
    r3.cmd( 'ip route add 10.0.0.0/24 via 180.1.2.2 dev r3-eth1' )
    r3.cmd( 'ip route add 192.168.1.0/24 via 180.1.2.2 dev r3-eth1' )
    r3.cmd( 'ip route add 10.8.1.0/24 via 180.1.2.2 dev r3-eth1' )

    # r4 routes to 10.0.0.0/24 via 180.1.2.1; to 11.0.0.0/24 via 180.1.2.1; to 192.168.1.0/24 via 170.0.0.1
    r4.cmd( 'ip route add 10.0.0.0/24 via 180.1.2.1 dev r4-eth0' )
    r4.cmd( 'ip route add 11.0.0.0/24 via 180.1.2.1 dev r4-eth0' )
    r4.cmd( 'ip route add 192.168.1.0/24 via 170.0.0.1 dev r4-eth2' )

    info( '*** Ready. Launching CLI\n' )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    build()

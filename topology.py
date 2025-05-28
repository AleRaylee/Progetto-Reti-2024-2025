from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel


    
class Topology(Topo):
    def build(self):
    
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch) 
        
    #Aggiungiamo gli Host
    H1 = self.addHost('h1', ip = '10.0.0.1/24', defaultRoute = 'via 10.0.0.254')
    H2 = self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
    H3 = self.addHost('h3', ip='11.0.0.1/24', defaultRoute='via 11.0.0.254')
    H4 = self.addHost('h4', ip='192.168.1.1/24', defaultRoute='via 192.168.1.254')
    H5 = self.addHost('h5', ip='10.8.1.1/24', defaultRoute='via 10.8.1.254')
    
    #Aggiungi router 
    r1 = self.addHost('r1')
    r2 = self.addHost('r2')
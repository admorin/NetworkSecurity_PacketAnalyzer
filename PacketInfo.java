public class PacketInfo{

	private boolean eth,ip,arp,udp,tcp,icmp = false;
	private String[] ethinfo;
	private String[] ipinfo;
	private String[] arpinfo;
	private String[] udpinfo;
	private String[] tcpinfo;
	private String[] icmpinfo;

	public void setInfo(String layer, String[] info){
		switch(layer){
			case "ETH":
			    this.ethinfo = info;
			    eth = true;
			    break;
			case "IP":
			    this.ipinfo = info;
			    ip = true;
			    break;
			case "ARP":
			    this.arpinfo = info;
			    arp = true;
			    break;
			case "UDP":
			    this.udpinfo = info;
			    udp = true;
			    break;
			case "TCP":
			    this.tcpinfo = info;
			    tcp = true;
			    break;
			case "ICMP":
			    this.icmpinfo = info;
			    icmp = true;
			    break;
			default:
			    System.out.println("ERROR: Invalid layer - " + layer);
		}
	}

	public String[] getLayerInfo(String layer){
		switch(layer){
			case "ETH":
			    if(eth) return ethinfo;
			case "IP":
			    if(ip) return ipinfo;
			case "ARP":
			    if(arp) return arpinfo;
			case "UDP":
			    if(udp) return udpinfo;
			case "TCP":
			    if(tcp) return tcpinfo;
			case "ICMP":
			    if(icmp) return icmpinfo;
			default:
			    System.out.println("ERROR: Layer not set!");
			    return null;
		}
	}
}
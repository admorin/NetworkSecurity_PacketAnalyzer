import java.util.*;

public class PacketInfo{

	private boolean eth,ip,arp,udp,tcp,icmp = false;
	private LinkedList<String> protocols = new LinkedList<String>();
	private String[] ethinfo;
	private String[] ipinfo;
	private String[] arpinfo;
	private String[] udpinfo;
	private String[] tcpinfo;
	private String[] icmpinfo;

	public void setInfo(String layer, String[] info){
		protocols.add(layer);
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

	public String[] getProtocols(){
		return protocols.toArray(new String[protocols.size()]);
	}

	public String[] getIPs(){
		if(protocols.get(1).equals("IP")){
			if(ipinfo.length > 0){
				return new String[] {ipinfo[9], ipinfo[10]};
			} else {
				System.out.println("ERROR: No IP info!");
				return null;
			}
		} else if(protocols.get(1).equals("ARP")) {
			if(arpinfo.length > 0){
				return new String[] {arpinfo[6], arpinfo[8]};
			}
		}
		System.out.println("Error in getIPs!");
		return null;
		
	}

	public String[] getPorts(){
		if(protocols.get(1).equals("ARP")){
			return null;
		}
		if(protocols.get(2).equals("TCP")){
			return new String[] {tcpinfo[0], tcpinfo[1]};
		} else if(protocols.get(2).equals("UDP")){
			return new String[] {udpinfo[0], udpinfo[1]};
		} else if(protocols.get(2).equals("ICMP")){
			return new String[] {"0", "0"};
		} else {
			// System.out.println("ERROR: No port info!");
			return null;
		}
	}

	public int[] ipInts(){
		if(protocols.get(1).equals("IP")){
			return new int[] {Integer.parseInt(ipinfo[6]),
			 Integer.parseInt(ipinfo[2]), 
			 Integer.parseInt(ipinfo[4], 16), 
			 Integer.parseInt(ipinfo[5])}; //TTl, TOS, ID, OFFSET
		} else {
			// System.out.println("ERROR: Not an IP packet!");
			return null;
		}
		
	}

	public String[] getIPOpts(){
		if(protocols.get(1).equals("IP")){
			return new String[] {ipinfo[11]};
		} else {
			// System.out.println("ERROR: Not an IP packet!");
			return null;
		}
	}

	public String getFragBits(){
		if(protocols.get(1).equals("IP")){
			return ipinfo[12];
		} else {
			// System.out.println("ERROR: Not an IP packet!");
			return null;
		}
	}

	public String getOGPacket(){
		return ethinfo[4];
	}

	public String getPayload(){
		if(protocols.get(1).equals("IP")){
			if(protocols.get(2).equals("TCP")){
				return tcpinfo[18];
			} else if(protocols.get(2).equals("UDP")){
				return udpinfo[4];
			} else if(protocols.get(2).equals("ICMP")){
				return icmpinfo[6];
			} else {
				System.out.println("ERROR: Unknown IP Protocol!");
				return null;
			}
		} else if(protocols.get(1).equals("ARP")){
			return arpinfo[9];
		} else {
			// System.out.println("ERROR: Not an ARP packet!");
			return null;
		}
	}

	public int[] tcpInts(){
		if(protocols.size() > 2 && protocols.get(2).equals("TCP")){ //6-14
			String flags = "";
			for(int i = 6; i <= 14; i++){
				flags += tcpinfo[i];
			}
			return new int[] {Integer.parseInt(flags.substring(1), 2), 
				              Integer.parseInt(tcpinfo[2], 16), 
		                      Integer.parseInt(tcpinfo[3], 16)};
		} else {
			// System.out.println("ERROR: Not a TCP packet!");
			return null;
		}
	}

	public int[] icmpInts(){
		if(protocols.size() > 2 && protocols.get(2).equals("ICMP")){
			return new int[] {Integer.parseInt(icmpinfo[0]), 
				Integer.parseInt(icmpinfo[1])};
		} else {
			// System.out.println("ERROR: Not an ICMP packet!");
			return null;
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
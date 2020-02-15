public class EthernetAnalyzer{

	// Ethertypes:
	//     0800 - IPv4
	//     0806 - ARP
	// My MAC Address for checks:
	//     a4:83:e7:9c:8e:2c

	boolean valid = false;
	String packet = "";
	NetworkPacket netPack;
	final String type = "eth";

	public EthernetAnalyzer(String packet){
		this.packet = packet;
	}

	String[] getInfo(){
		String destMAC = getAddress(getBytes(6));
		String sourceMAC = getAddress(getBytes(6));
		String etherType = getBytes(2);
		String[] thisInfo = {sourceMAC, destMAC, etherType};
		if (etherType.equals("0800")){ // IPv4
			netPack = new IPAnalyzer(packet);
			return thisInfo + netPack.getInfo();
		} else if (etherType.equals("0806")){
			netPack = new ARPAnalyzer(packet);
			return thisInfo + netPack.getInfo();
		} else {
			return null;
		}
	}

	String getBytes(int amount){
		String requested = packet.substring(0,(amount*2));
		packet = packet.substring(amount*2);
		return requested;
	}

	boolean isType(String filter){
		if (filter.equals(type) || filter.equals("")){
			return true;
		} else {
			return netPack.isType(filter);
		}
	}

	String getAddress(String mac){
		String address = "";
		for (int i = 0; i < mac.length(); i+=2){
			if (i == 0){
				address = address + mac.substring(0,2);
			} else {
			    address = address + ":" + mac.substring(i, i+2);
			}
		}
		return address;
	}

	String prettyPrint(String srcMac, String dstMac, String etherType){
		if (etherType.equals("0800")){
			etherType = "IPv4";
		} else if(etherType.equals("0806")){
			etherType = "ARP ";
		}
		String thisInfo = 
		"+======================================================================================+\n" +
		"|                                    Ethernet Header                                   |\n" +
		"+======================================================================================+\n" +
		"| Source MAC: " + srcMac + " | Destination MAC: " + dstMac + " | EtherType: " + etherType + " |\n" +
		"+-------------------------------+------------------------------------+-----------------+\n" +
		"|          |          |          |          |          |          |          |         |\n" +
		"v          v          v          v          v          v          v          v         v\n";
		return thisInfo;
	}	
}
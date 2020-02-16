public class EthernetAnalyzer implements NetworkPacket{

	// Ethertypes:
	//     0800 - IPv4
	//     0806 - ARP
	// My MAC Address for checks:
	//     a4:83:e7:9c:8e:2c

	boolean valid = false;
	String packet = "";
	private String[] thisLayer;
	NetworkPacket nextPack;
	final String type = "eth";

	public EthernetAnalyzer(String packet){
		this.packet = packet;
	}

	public void getInfo(){
		String destMAC = getAddress(getBytes(6));
		String sourceMAC = getAddress(getBytes(6));
		String etherType = getBytes(2);
		thisLayer = {sourceMAC, destMAC, etherType};
		if (etherType.equals("0800")){ // IPv4
			nextPack = new IPAnalyzer(packet);
			nextPack.getInfo();
		} else if (etherType.equals("0806")){
			nextPack = new ARPAnalyzer(packet);
			nextPack.getInfo();
		}
	}

	private String getBytes(int amount){
		String requested = packet.substring(0,(amount*2));
		packet = packet.substring(amount*2);
		return requested;
	}

	public boolean isType(String filter){
		if (filter.equals(type) || filter.equals("")){
			return true;
		} else {
			return nextPack.isType(filter);
		}
	}

	private String getAddress(String mac){
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

	public String prettyPrint(String[] allInfo, boolean onlyHeader){
		if (allInfo[2].equals("0800")){
			allInfo[2] = "IPv4";
		} else if(allInfo[2].equals("0806")){
			allInfo[2] = "ARP ";
		}
		String thisInfo = 
		"+======================================================================================+\n" +
		"|                                    Ethernet Header                                   |\n" +
		"+======================================================================================+\n" +
		"| Source MAC: " + allInfo[0] + " | Destination MAC: " + allInfo[1] + " | EtherType: " + allInfo[2] + " |\n" +
		"+-------------------------------+------------------------------------+-----------------+\n" +
		"|          |          |          |          |          |          |          |         |\n" +
		"v          v          v          v          v          v          v          v         v\n";
		return thisInfo;
	}	
}
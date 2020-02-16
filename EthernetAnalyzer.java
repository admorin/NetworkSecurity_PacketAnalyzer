public class EthernetAnalyzer implements NetworkPacket{

	// Ethertypes:
	//     0800 - IPv4
	//     0806 - ARP
	// My MAC Address for checks:
	//     a4:83:e7:9c:8e:2c

	boolean valid = false;
	String packet = "";
	private String[] thisLayer = new String[3];
	private NetworkPacket nextPack;
	final String type = "eth";

	public EthernetAnalyzer(String packet){
		this.packet = packet;
	}

	public void getInfo(){
		thisLayer[0] = getAddress(getBytes(6));
		thisLayer[1] = getAddress(getBytes(6));
		thisLayer[2] = getBytes(2);
		if (thisLayer[2].equals("0800")){ // IPv4
			nextPack = new IPAnalyzer(packet);
			nextPack.getInfo();
		} else if (thisLayer[2].equals("0806")){
			nextPack = new ARPAnalyzer(packet);
			nextPack.getInfo();
		}
	}

	public boolean isValid(){
		if (nextPack != null){
			return true;
		} else {
			return false;
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

	public String prettyPrint(boolean headerFlag, String typeFlag){
		if (thisLayer[2].equals("0800")){
			thisLayer[2] = "IPv4";
		} else if(thisLayer[2].equals("0806")){
			thisLayer[2] = "ARP ";
		}
		if (headerFlag && !typeFlag.equals(type)){
			return "" + nextPack.prettyPrint(headerFlag, typeFlag);
		} else {
			String thisInfo = 
			"+======================================================================================+\n" +
			"|                                    Ethernet Header                                   |\n" +
			"+======================================================================================+\n" +
			"| Source MAC: " + thisLayer[0] + " | Destination MAC: " + thisLayer[1] + " | EtherType: " + thisLayer[2] + " |\n" +
			"+-------------------------------+------------------------------------+-----------------+\n";
		    return thisInfo + nextPack.prettyPrint(headerFlag, typeFlag);
		}
	}
}
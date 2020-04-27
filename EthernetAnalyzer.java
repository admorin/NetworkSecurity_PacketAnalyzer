public class EthernetAnalyzer implements NetworkPacket{

	// Ethertypes:
	//     0800 - IPv4
	//     0806 - ARP
	// My MAC Address for checks:
	//     a4:83:e7:9c:8e:2c

	boolean valid = false;
	String packet = "";
	String ogPacket = "";
	private PacketInfo packetInfo;
	private String[] thisLayer = new String[5];
	private NetworkPacket nextPack;
	final String type = "eth";

	public EthernetAnalyzer(String packet){
		this.packet = packet;
		this.ogPacket = packet;
	}

	public void getInfo(PacketInfo packetInfo){
		thisLayer[0] = getAddress(getBytes(6)); //Source MAC
		thisLayer[1] = getAddress(getBytes(6)); //Dest MAC
		thisLayer[2] = getBytes(2); //Protocol
		thisLayer[3] = packet;
		thisLayer[4] = ogPacket;
		packetInfo.setInfo("ETH", thisLayer);
		if (thisLayer[2].equals("0800")){ // IPv4
			nextPack = new IPAnalyzer(packet);
			nextPack.getInfo(packetInfo);
		} else if (thisLayer[2].equals("0806")){ // ARP
			nextPack = new ARPAnalyzer(packet);
			nextPack.getInfo(packetInfo);
		} else if (thisLayer[2].equals("86DD")){
			nextPack = new IPAnalyzer(packet);
			nextPack.getInfo(packetInfo);
		} else {
			System.out.println("Invalid Protocol: " + thisLayer[2]);
			System.out.println(thisLayer[0] + "\n" + thisLayer[1]);
		}
	}

	public String getID(){
		return nextPack.getID();
	}

	public boolean validateChecksum(){
		return nextPack.validateChecksum();
	}

	public boolean isFragmented(){
		if(nextPack instanceof IPAnalyzer){
			return nextPack.isFragmented();
		} else {
			// System.out.println("ERROR: This packet is not an IP packet!");
			return false;
		}
	}

	public String[] getFragInfo(){
		return nextPack.getFragInfo();
	}

	public boolean isValid(){
		if (nextPack != null){
			return true;
		} else {
			return false;
		}
	}

	public PacketInfo replyInfo(){
		return packetInfo;
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

	private String getReadable(){
		String thisInfo = 
			"+======================================================================================+\n" +
			"|                                    Ethernet Header                                   |\n" +
			"+======================================================================================+\n" +
			"| Source MAC: " + thisLayer[0] + " | Destination MAC: " + thisLayer[1] + " | EtherType: " + thisLayer[2] + " |\n" +
			"+-------------------------------+------------------------------------+-----------------+\n";
		return thisInfo;
	}

	public String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions){
		if (thisLayer[2].equals("0800")){
			thisLayer[2] = "IPv4";
		} else if(thisLayer[2].equals("0806")){
			thisLayer[2] = "ARP ";
		}
		if (conditions[0].equals("") || conditions[0].equals(type)){
			conditions[0] = "";
		}
		String nextHeader = nextPack.prettyPrint(headerFlag, andFlag, orFlag, conditions);
		if(nextHeader.equals("")){
			return "";
		} else {
			return getReadable() + nextHeader;
		}
	}
}









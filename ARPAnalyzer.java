public class ARPAnalyzer implements NetworkPacket{

	String packet = "";
	private String[] thisLayer;
	final String type = "arp";

	public ARPAnalyzer(String packet){
		this.packet = packet;
	}

	public void getInfo(){
		String hwtype = getBytes(2);
		String prtype = getBytes(2);
		String hwaddl = getBytes(1);
		String praddl = getBytes(1);
		String oper = getBytes(2);
		String sha = getAddress(getBytes(6));
		String spa = getIP(getBytes(4));
		String tha = getAddress(getBytes(6));
		String tpa = getIP(getBytes(4));
		thisLayer = {hwtype, prtype, hwaddl, praddl, oper, sha, spa, tha, tpa};
	}

	public String getBytes(int amount){
		String requested = packet.substring(0,(amount*2));
		packet = packet.substring(amount*2);
		return requested;
	}

	public String getAddress(String mac){
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

	public String getIP(String ip){
		String address = "";
		for (int i = 0; i < ip.length(); i+=2){
			if (i == 0){
				address = address + String.valueOf(Integer.parseInt(ip.substring(i,i+2),16));
			} else {
			    address = address + "." + String.valueOf(Integer.parseInt(ip.substring(i,i+2),16));
			}
		}
		int extraSpace = 15 - address.length();
		for (int i = 0; i < extraSpace; i++){
			address = address + " ";
		}
		return address;
	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
		}
	}

	public String prettyPrint(String[] allInfo, boolean onlyHeader){
		if (allInfo[0].equals("0001")){
			allInfo[0] = "Ethernet";
		}
		if(allInfo[1].equals("0800")){
			allInfo[1] = "IPv4";
		}
		String thisInfo = 
		"+======================================================================================+\n" +
		"|                                    ARP Header                                        |\n" +
		"+======================================================================================+\n" +
		"| Hardware Type: " + allInfo[0] + "       | Protocol Type: " + allInfo[1] + "        | Hardware Add Length: " + allInfo[2] + " |\n" +
		"+-------------------------------+----------------------------+-------------------------+\n" +
		"| Protocol Addr Length: " + allInfo[3] + "      | Operation: " + allInfo[4] + "                                      |\n" +
		"+-------------------------------+------------------------------------------------------+\n" +
		"| Sender MAC: " + allInfo[5] + " | Sender IP: " + allInfo[6] + "                           |\n" +
		"+-------------------------------+------------------------------------------------------+\n" +
		"| Target MAC: " + allInfo[7] + " | Target IP: " + allInfo[8] + "                           |\n" +
		"+-------------------------------+------------------------------------------------------+\n\n\n";
		return thisInfo;
	}	
	
}
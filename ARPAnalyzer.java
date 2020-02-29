public class ARPAnalyzer implements NetworkPacket{

	String packet = "";
	private String[] thisLayer = new String[9];
	final String type = "arp";

	public ARPAnalyzer(String packet){
		this.packet = packet;
	}

	public void getInfo(){
		thisLayer[0] = getBytes(2); // Hardware Type
		thisLayer[1] = getBytes(2); // Protocol Type
		thisLayer[2] = getBytes(1); // Hardware Address Length
		thisLayer[3] = getBytes(1); // Protocol Address Length
		thisLayer[4] = getBytes(2); // Operation Type
		thisLayer[5] = getAddress(getBytes(6)); // Sender MAC
		thisLayer[6] = getIP(getBytes(4)); // Sender IP
		thisLayer[7] = getAddress(getBytes(6)); // Target MAC
		thisLayer[8] = getIP(getBytes(4)); // Target IP
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

	private String hexToAscii(String hexStr) {
        StringBuilder output = new StringBuilder("");
     
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

	private String getReadable(boolean headflag){
		String thisInfo = 
			"+======================================================================================+\n" +
			"|                                    ARP Header                                        |\n" +
			"+======================================================================================+\n" +
			"| Hardware Type: " + thisLayer[0] + "       | Protocol Type: " + thisLayer[1] + "        | Hardware Add Length: " + thisLayer[2] + " |\n" +
			"+-------------------------------+----------------------------+-------------------------+\n" +
			"| Protocol Addr Length: " + thisLayer[3] + "      | Operation: " + thisLayer[4] + "                                      |\n" +
			"+-------------------------------+------------------------------------------------------+\n" +
			"| Sender MAC: " + thisLayer[5] + " | Sender IP: " + thisLayer[6] + "                           |\n" +
			"+-------------------------------+------------------------------------------------------+\n" +
			"| Target MAC: " + thisLayer[7] + " | Target IP: " + thisLayer[8] + "                           |\n" +
			"+-------------------------------+------------------------------------------------------+\n\n";
			if (!headflag){
				thisInfo = thisInfo + "PAYLOAD: \n" + hexToAscii(packet) + "\n";
			}
		return thisInfo;
	}

	public String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions){
		if (thisLayer[0].equals("0001")){
			thisLayer[0] = "Ethernet";
		}
		if(thisLayer[1].equals("0800")){
			thisLayer[1] = "IPv4";
		}
		if (!conditions[0].equals("") && !conditions[0].equals(type)){
			return "";
		}
		if (orFlag){
		    if (conditions[1].equals(thisLayer[6].trim()) || conditions[2].equals(thisLayer[8].trim())){
			    return getReadable(headerFlag);
			} else {
				return "";
			}
		} else if (andFlag){
			if (conditions[1].equals(thisLayer[6].trim()) && conditions[2].equals(thisLayer[8].trim())){
				return getReadable(headerFlag);
			} else {
				return "";
			}
		}
		return getReadable(headerFlag);	
		// If headflag set, don't return payload.
	}	
	
}
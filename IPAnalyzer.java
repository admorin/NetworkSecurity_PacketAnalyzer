public class IPAnalyzer implements NetworkPacket{

	// Protocols:
    // 0x06 = TCP
    // 0x11 = UDP
    // 0x01 = ICMP

    String packet = "";
    private String[] thisLayer = new String[12];
    final String type = "ip";

    public IPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){
		String versANDihl = getBytes(1);
		thisLayer[0] = String.valueOf(versANDihl.charAt(0)); // Version
		thisLayer[1] = String.valueOf(versANDihl.charAt(1)); // IHL
		int headerlen = Integer.parseInt(thisLayer[1]);
		thisLayer[2] = getBytes(1); // DSCP/ECN
		thisLayer[3] = getBytes(2); // Total Length
		thisLayer[3] = String.valueOf(Integer.parseInt(thisLayer[3],16));
		thisLayer[4] = getBytes(2); // Identification
		thisLayer[5] = getBytes(2); // Offset
		thisLayer[5] = String.valueOf(Integer.parseInt(thisLayer[5],16));
		thisLayer[6] = getBytes(1); // Time to Live
		thisLayer[6] = String.valueOf(Integer.parseInt(thisLayer[6], 16));
		thisLayer[7] = getProtocol(getBytes(1)); // Protocol
		thisLayer[8] = "0x" + getBytes(2); // Header Checksum
		thisLayer[9] = getIP(getBytes(4)); // Source IP
		thisLayer[10] = getIP(getBytes(4)); // Destination IP
		thisLayer[11] = ""; // Options
		if (headerlen > 5){
			thisLayer[11] = getOptions(headerlen);
		}
		// thisLayer = {version, ihl, dscpecn, totallength, identification, offset, time2live, protocol, headerCS,
		//     srcIP, destIP, options};
	}

	public String getBytes(int amount){
		String requested = packet.substring(0,(amount*2));
		packet = packet.substring(amount*2);
		return requested;
	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
		}
	}

	public String getProtocol(String hex){
		if(hex.equals("06")){
			return "TCP ";
		} else if(hex.equals("11")){
			return("UDP ");
		} else if(hex.equals("01")){
			return("ICMP");
		} else {
			return "NONE";
		}
	}

	public String formatString(String input, int target){
		String output = input;
		int extraSpace = target - input.length();
		for (int i = 0; i < extraSpace; i++){
			output = output + " ";
		}
		return output;
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

	public String getOptions(int headerlen){
		int bytes2get = (headerlen-5) * 4; // 4 bytes per line, and headerlen is how many lines are in options.
		String options = getBytes(bytes2get);
		String optionsString = "";
		for (int i = 0; i < (headerlen-5); i+=4){
			optionsString = optionsString + getBytes(4) + " ";
		}
		return formatString(optionsString, 49);
	}

	public String prettyPrint(boolean headerFlag, String typeFlag){
		String totallength = formatString(thisLayer[3], 5);
		String offset = formatString(thisLayer[5], 5);
		String time2live = formatString(thisLayer[6], 3);
		if (headerFlag && !typeFlag.equals(type)){
			return "";
		} else {
			String thisInfo = 
			"+======================================================================================+\n" +
			"|                                     IP Header                                        |\n" +
			"+======================================================================================+\n" +
			"| Version: " + thisLayer[0] + "     | Header Length: " + thisLayer[1] + "     | DSCP/ECN: " + thisLayer[2] + "     | Total Length: " + totallength + "       |\n" + 
			"+----------------+----------------------+------------------+---------------------------+\n" +
			"| Identification: " + thisLayer[4] + "                  | Offset: " + offset + "    | Time to Live: " + time2live + "         |\n" +
			"+---------------------------------------+------------------+---------------------------+\n" +
			"| Protocol: " + thisLayer[7] + "                        | Checksum: " + thisLayer[8] + "                             |\n" +
			"+---------------------------------------+----------------------------------------------+\n" +
			"| Source IP: " + thisLayer[9] + "            | Dest IP: " + thisLayer[10] + "                     |\n";
			if (thisLayer[11].equals("")){
				thisInfo = thisInfo + 
				"+---------------------------------------+----------------------------------------------+\n\n\n";
			} else {
				thisInfo = thisInfo +
				"+---------------------------------------+----------------------------------------------+\n" +
			    "| Options: " + thisLayer[11] + "                           |\n" +
			    "+---------------------------------------+----------------------------------------------+\n";
			}
		    return thisInfo;
		}
	}	
	
}
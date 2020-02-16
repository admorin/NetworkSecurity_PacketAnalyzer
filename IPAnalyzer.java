public class IPAnalyzer implements NetworkPacket{

	// Protocols:
    // 0x06 = TCP
    // 0x11 = UDP
    // 0x01 = ICMP

    String packet = "";
    private String[] thisLayer;
    final String type = "ip";

    public IPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){
		String versANDihl = getBytes(1);
		String version = String.valueOf(versANDihl.charAt(0));
		String ihl = String.valueOf(versANDihl.charAt(1));
		int headerlen = Integer.parseInt(ihl);
		String options = "";
		String dscpecn = getBytes(1);
		String totallength = getBytes(2);
		totallength = String.valueOf(Integer.parseInt(totallength,16));
		String identification = getBytes(2);
		String offset = getBytes(2);
		offset = String.valueOf(Integer.parseInt(offset,16));
		String time2live = getBytes(1);
		time2live = String.valueOf(Integer.parseInt(time2live, 16));
		String protocol = getProtocol(getBytes(1));
		String headerCS = "0x" + getBytes(2);
		String srcIP = getIP(getBytes(4)); //12-15
		String destIP = getIP(getBytes(4)); //16-19
		if (headerlen > 5){
			options = getOptions(headerlen);
		}
		thisLayer = {version, ihl, dscpecn, totallength, identification, offset, time2live, protocol, headerCS,
		    srcIP, destIP, options};
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

	public String prettyPrint(String[] allInfo, boolean onlyHeader){
		String totallength = formatString(allInfo[3], 5);
		String offset = formatString(allInfo[5], 5);
		String time2live = formatString(allInfo[6], 3);
		String thisInfo = 
		"+======================================================================================+\n" +
		"|                                     IP Header                                        |\n" +
		"+======================================================================================+\n" +
		"| Version: " + allInfo[0] + "     | Header Length: " + allInfo[1] + "     | DSCP/ECN: " + allInfo[2] + "     | Total Length: " + totallength + "       |\n" + 
		"+----------------+----------------------+------------------+---------------------------+\n" +
		"| Identification: " + allInfo[4] + "                  | Offset: " + offset + "    | Time to Live: " + time2live + "         |\n" +
		"+---------------------------------------+------------------+---------------------------+\n" +
		"| Protocol: " + allInfo[7] + "                        | Checksum: " + allInfo[8] + "                             |\n" +
		"+---------------------------------------+----------------------------------------------+\n" +
		"| Source IP: " + allInfo[9] + "            | Dest IP: " + allInfo[10] + "                     |\n";
		if (allInfo[11].equals("")){
			thisInfo = thisInfo + 
			"+---------------------------------------+----------------------------------------------+\n\n\n";
		} else {
			thisInfo = thisInfo +
			"+---------------------------------------+----------------------------------------------+\n" +
		    "| Options: " + allInfo[11] + "                           |\n" +
		    "+---------------------------------------+----------------------------------------------+\n\n\n";
		}
		return thisInfo;
	}	
	
}
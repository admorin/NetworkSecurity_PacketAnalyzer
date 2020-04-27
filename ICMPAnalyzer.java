import java.math.BigInteger;

public class ICMPAnalyzer implements NetworkPacket {
	
	String packet = "";
	String ogPacket = "";
    private String[] thisLayer = new String[7];
    final String type = "icmp";

    public ICMPAnalyzer(String packet){
    	this.packet = packet;
    	this.ogPacket = packet;
    }

	public void getInfo(PacketInfo packetInfo){
		String[] typeANDcode = typeCode(getBytes(2)); // TypeANDCode
		thisLayer[0] = typeANDcode[0];
		thisLayer[1] = typeANDcode[1];
		thisLayer[2] = getBytes(2); // Checksum
		thisLayer[3] = formatString(typeANDcode[2], 41);
		thisLayer[4] = formatString(getBytes(4),41); // Rest of Header
		thisLayer[6] = packet;
		packetInfo.setInfo("ICMP", thisLayer);
	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
		}
	}

	public boolean validateChecksum(){
		return true;
	}


    // NOT FULLY IMPLEMENTED ON ICMP
	private boolean calcChecksum(String headerRaw){
		String[] header = headerRaw.split("(?<=\\G....)");
		BigInteger bi1 = new BigInteger(header[0], 16);
		for(int i = 1; i < header.length; i++){
			bi1 = bi1.add(new BigInteger(header[i], 16));
		}
		String bihex;
		while(bi1.intValue() > 0xFFFF){
			bihex = bi1.toString(16);
			bi1 = new BigInteger("000" + bihex.charAt(0)).add(new BigInteger(bihex.substring(1,5), 16));
		}
		String checksum = bi1.toString(16);
		return checksum.equals("ffff");
	}


	public boolean isFragmented(){
		return false;
	}

	public String getID(){
		return null;
	}

	public String[] getFragInfo(){
		return null;
	}

	private String[] typeCode(String typeAndCode){
		// System.out.println(typeAndCode);
		int type = Integer.parseInt(typeAndCode.substring(0,2),16);
		int code = Integer.parseInt(typeAndCode.substring(2,4),16);
		String key = "ICMP123" + String.valueOf(type) + String.valueOf(code);
		ICMPTypes thisMsg = ICMPTypes.valueOf(key);
		String response = thisMsg.getMessage();
		String[] allInfo = {String.valueOf(type), String.valueOf(code), response};
		return allInfo;
	}

	public String getBytes(int amount){
		int realLength = packet.length()/2;
		if (realLength < amount){
			amount = realLength;
		}
		String requested = packet.substring(0,(amount*2));
		packet = packet.substring(amount*2);
		return requested;
	}

	public String formatString(String input, int target){
		String output = input;
		int extraSpace = target - input.length();
		for (int i = 0; i < extraSpace; i++){
			output = output + " ";
		}
		return output;
	}

	public String getOptions(int headerlen){
		int bytes2get = (headerlen-5) * 4; // 4 bytes per line, and headerlen is how many lines are in options.
		String options = getBytes(bytes2get);
		return formatString(options, 49); // This needs to be worked on, there are three options fields.
	}

	private String hexToAscii(String hexStr) {
        StringBuilder output = new StringBuilder("");
     
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

	private String getReadable(boolean headerFlag){
		String thisInfo = 
			"+======================================================================================+\n" +
			"|                                    ICMP Header                                       |\n" +
			"+======================================================================================+\n" +
			"| Type: " + formatString(thisLayer[0],2) + "       | Code: " + formatString(thisLayer[1], 2) + "             | Checksum: " + thisLayer[2] + "                               |\n" + 
			"+----------------+----------------------+----------------------------------------------+\n" +
			"| Description: " + thisLayer[3] + "                               |\n" +
			"+--------------------------------------------------------------------------------------+\n" +
			"| Rest of Header: " + thisLayer[4] + "                            |\n" +
			"+--------------------------------------------------------------------------------------+\n";
			if(!headerFlag){
				thisInfo = thisInfo + "PAYLOAD: \n" + hexToAscii(packet) + "\n";
			}
		    return thisInfo;
	}

	public String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions){
		if (!conditions[0].equals("") && !conditions[0].equals(type)){
			return "";
		} else {
			return getReadable(headerFlag);
		}
	}

}
public class ICMPAnalyzer implements NetworkPacket {
	
	String packet = "";
    private String[] thisLayer = new String[6];
    final String type = "icmp";

    public ICMPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){
		String[] typeANDcode = typeCode(getBytes(2)); // TypeANDCode
		thisLayer[0] = typeANDcode[0];
		thisLayer[1] = typeANDcode[1];
		thisLayer[2] = getBytes(2); // Checksum
		thisLayer[3] = formatString(typeANDcode[2], 41);
		thisLayer[4] = formatString(getBytes(4),41); // Rest of Header
	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
		}
	}

	private String[] typeCode(String typeAndCode){
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

	private String getReadable(){
		String thisInfo = 
			"+======================================================================================+\n" +
			"|                                    ICMP Header                                       |\n" +
			"+======================================================================================+\n" +
			"| Type: " + formatString(thisLayer[0],2) + "       | Code: " + formatString(thisLayer[1], 2) + "             | Checksum: " + thisLayer[2] + "                               |\n" + 
			"+----------------+----------------------+----------------------------------------------+\n" +
			"| Description: " + thisLayer[3] + "                               |\n" +
			"+--------------------------------------------------------------------------------------+\n" +
			"| Rest of Header: " + thisLayer[4] + "                            |\n";
			if (packet.length() == 0){
				thisInfo = thisInfo + 
				"+--------------------------------------------------------------------------------------+\n\n\n";
			} else {
				thisInfo = thisInfo +
				"+--------------------------------------------------------------------------------------+\n" +
			    "| Data: " + formatString(getBytes(39), 78) + " |\n";
			    String thisDat;
			    while ((thisDat = getBytes(42)).length() > 0){
			    	thisInfo = thisInfo + "| " + formatString(thisDat, 84) + " |\n";
			    }
			    thisInfo = thisInfo +
			    "+--------------------------------------------------------------------------------------+\n";
			}
		    return thisInfo;
	}

	public String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions){
		if (headerFlag && !conditions[0].equals(type)){
			return "";
		}
		return getReadable();
	}

}
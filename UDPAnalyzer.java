public class UDPAnalyzer implements NetworkPacket {

	String packet = "";
    private String[] thisLayer = new String[4];
    final String type = "udp";

    public UDPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){
		thisLayer[0] = getPort(getBytes(2)); // Source Port
		thisLayer[1] = getPort(getBytes(2)); // Destination Port
		thisLayer[2] = String.valueOf(Integer.parseInt(getBytes(2),16)); // Length
		thisLayer[3] = String.valueOf(Integer.parseInt(getBytes(2),16)); // Checksum
	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
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

	private String getPort(String hexPort){
		return formatString(String.valueOf(Integer.parseInt(hexPort, 16)),5);
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

	private String getReadable(){
		String thisInfo = 
			"+======================================================================================+\n" +
			"|                                    UDP Header                                        |\n" +
			"+======================================================================================+\n" +
			"| Source Port: " + formatString(thisLayer[0],25) + " | Destination Port: " + formatString(thisLayer[1], 25) + " |\n" + 
			"+----------------------------------------+---------------------------------------------+\n" +
			"| Length: " + formatString(thisLayer[3], 30) + " | Checksum: " + formatString(thisLayer[3], 33) + " |\n";
			if (packet.length() == 0){
				thisInfo = thisInfo + 
				"+----------------------------------------+---------------------------------------------+\n\n\n";
			} else {
				thisInfo = thisInfo +
				"+----------------------------------------+---------------------------------------------+\n" +
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
		} else if(!conditions[3].equals("")){ // There is a SOURCE port restriction
			int prt1 = Integer.parseInt(conditions[3]);
			int prt2 = Integer.parseInt(conditions[4]);
			int thisprt = Integer.parseInt(thisLayer[0]);
			if (prt2 < prt1) {
				int temp = prt1;
				prt1 = prt2;
				prt2 = temp;
			}
			if(thisprt >= prt1 && thisprt <= prt2){
				return getReadable();
			}
			return "";
		} else if(!conditions[5].equals("")){ // There is a DEST port restriction
			int prt1 = Integer.parseInt(conditions[5]);
			int prt2 = Integer.parseInt(conditions[6]);
			int thisprt = Integer.parseInt(thisLayer[1]);
			if (prt2 < prt1) {
				int temp = prt1;
				prt1 = prt2;
				prt2 = temp;
			}
			if(thisprt >= prt1 && thisprt <= prt2){
				return getReadable();
			}
			return "";
		}
		return getReadable();
	}
}
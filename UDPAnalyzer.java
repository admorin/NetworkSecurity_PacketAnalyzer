public class UDPAnalyzer implements NetworkPacket {

	String packet = "";
    private String[] thisLayer = new String[4];
    final String type = "udp";
    private boolean dnsFlag = false;

    public UDPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){
		thisLayer[0] = getPort(getBytes(2)); // Source Port
		thisLayer[1] = getPort(getBytes(2)); // Destination Port
		if (thisLayer[0].equals("53")){
			dnsFlag = true;
		}
		thisLayer[2] = String.valueOf(Integer.parseInt(getBytes(2),16)); // Length
		thisLayer[3] = String.valueOf(Integer.parseInt(getBytes(2),16)); // Checksum
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

	public String formatString(String input, int target){
		String output = input;
		int extraSpace = target - input.length();
		for (int i = 0; i < extraSpace; i++){
			output = output + " ";
		}
		return output;
	}

	private String getPort(String hexPort){
		return formatString(String.valueOf(Integer.parseInt(hexPort, 16)),5).trim();
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

	private String getDNSName(){
		StringBuilder output = new StringBuilder("");
		while(true){
			int len = Integer.parseInt(getBytes(1), 16);
			if (len == 0) break;
			for (int i = 0; i < len; i ++) {
	            String str = getBytes(1);
	            output.append((char) Integer.parseInt(str, 16));
	        }
	        output.append(".");
		}
		return output.toString();
	}

	private String formatDNS(){
		int lengthData = Integer.parseInt(thisLayer[2]) - 8;
		String dnsMSG = 
		    "ID: " + getBytes(2) + "\n"+
		    "FLAGS: " + getBytes(2) + "\n"+
		    "QUESTIONS: " + Integer.parseInt(getBytes(2), 16) + "\n" +
		    "ANSWERS: " + Integer.parseInt(getBytes(2), 16) + "\n" +
		    "AUTH: " + Integer.parseInt(getBytes(2), 16) + "\n" +
		    "ADD: " + Integer.parseInt(getBytes(2), 16) + "\n" +
		    "NAME: " + getDNSName() + "\n" +
		    "TYPE: " + getBytes(2) + "\n" +
		    "CLASS: " + getBytes(2) + "\n" +
		    "POINTER: " + getBytes(2) + "\n" +
		    "TYPE: " + getBytes(2) + "\n" +
		    "CLASS: " + getBytes(2) + "\n" +
		    "TTL: " + getBytes(4) + "\n" +
		    "LENGTH: " + getBytes(2) + "\n" +
		    "ADDR: " + getIP(getBytes(4)) + "\n";
		return dnsMSG;
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
			"|                                    UDP Header                                        |\n" +
			"+======================================================================================+\n" +
			"| Source Port: " + formatString(thisLayer[0],25) + " | Destination Port: " + formatString(thisLayer[1], 25) + " |\n" + 
			"+----------------------------------------+---------------------------------------------+\n" +
			"| Length: " + formatString(thisLayer[2], 30) + " | Checksum: " + formatString(thisLayer[3], 33) + " |\n" +
			"+----------------------------------------+---------------------------------------------+\n";
		    if(!headerFlag){
		    	if (dnsFlag){
			        thisInfo = thisInfo + "PAYLOAD: \n" + formatDNS() + "\n" + hexToAscii(packet) + "\n";
		        } else {
				    thisInfo = thisInfo + "PAYLOAD: \n" + hexToAscii(packet) + "\n";
				}
			}
		    return thisInfo;
	}

	public String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions){
		if (!conditions[0].equals("") && !conditions[0].equals(type)){
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
				return getReadable(headerFlag);
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
				return getReadable(headerFlag);
			}
			return "";
		}
		return getReadable(headerFlag);
	}
}
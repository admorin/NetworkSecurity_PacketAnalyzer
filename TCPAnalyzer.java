public class TCPAnalyzer implements NetworkPacket {

	String packet = "";
    private String[] thisLayer = new String[18];
    private int headerlen = 5;
    final String type = "tcp";

    public TCPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){
		thisLayer[0] = getPort(getBytes(2)); // Source Port
		thisLayer[1] = getPort(getBytes(2)); // Destination Port
		thisLayer[2] = getBytes(4); // Sequence Number
		thisLayer[3] = getBytes(4); // Acknowledgement Number
		String offsetANDflags = hex2bin(getBytes(1)); // Offset and flags
		headerlen = Integer.parseInt(offsetANDflags.substring(0,4),2);
		thisLayer[4] = String.valueOf(headerlen); // Data Offset
		thisLayer[5] = offsetANDflags.substring(4,7); // Reserved
		thisLayer[6] = String.valueOf(offsetANDflags.charAt(7)); // NS
		offsetANDflags = hex2bin(getBytes(1));
		thisLayer[7] = String.valueOf(offsetANDflags.charAt(0)); // CWR
		thisLayer[8] = String.valueOf(offsetANDflags.charAt(1)); // ECE
		thisLayer[9] = String.valueOf(offsetANDflags.charAt(2)); // URG
		thisLayer[10] = String.valueOf(offsetANDflags.charAt(3)); // ACK
		thisLayer[11] = String.valueOf(offsetANDflags.charAt(4)); // PSH
		thisLayer[12] = String.valueOf(offsetANDflags.charAt(5)); // RST
		thisLayer[13] = String.valueOf(offsetANDflags.charAt(6)); // SYN
		thisLayer[14] = String.valueOf(offsetANDflags.charAt(7)); // FIN
		thisLayer[15] = getBytes(2);
		thisLayer[16] = getBytes(2);
		thisLayer[17] = getBytes(2);
	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
		}
	}

	private String getPort(String hexPort){
		return formatString(String.valueOf(Integer.parseInt(hexPort, 16)),5);
	}

	private String hex2bin(String hex){
		int val = Integer.parseInt(hex, 16);
		return String.format("%8s", Integer.toBinaryString(val)).replace(' ', '0');
	}

	public String getOptions(int headerlen){
		int bytes2get = (headerlen-5) * 4; // 4 bytes per line, and headerlen is how many lines are in options.
		String options = getBytes(bytes2get);
		return formatString(options, 49); // This needs to be worked on, there are three options fields.
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
			"|                                     TCP Header                                       |\n" +
			"+======================================================================================+\n" +
			"| Source Port: " + formatString(thisLayer[0], 20) + "     | Destination Port: " + formatString(thisLayer[1], 20) + "       |\n" +
			"+---------------------------------------+----------------------------------------------+\n" +
			"| Sequence Number: " + formatString(thisLayer[2], 15) + "      | Acknowledgement Number: " + formatString(thisLayer[3], 15) + "      |\n" + 
			"+----------------+---------------+------++--------+--------+--------+--------+---------+\n" +
			"| Data Off: " + formatString(thisLayer[4], 4) + " | Reserved: " + thisLayer[5] + " | NS: " + thisLayer[6] + " | CWR: " + thisLayer[7] + " | ECE: " +
			 thisLayer[8] + " | URG: " + thisLayer[9] + " | ACK: " + thisLayer[10] + " | PSH: " + thisLayer[11] + "  | \n" +
			"+--------+-------++--------+-----+-------+-----+--+--------+----+---+--------+---------+\n" +
			"| RST: " + thisLayer[12] + " | SYN: " + thisLayer[13] + " | FIN: " + thisLayer[14] + " | Window Size: " + thisLayer[15] +
			" | Checksum: " + thisLayer[16] + " | Urgent Pointer: " + thisLayer[17] + " |\n";
			if (headerlen <= 5){
				thisInfo = thisInfo + 
				"+--------+--------+--------+-------------------+----------------+----------------------+\n";
			} else {
				thisInfo = thisInfo +
				"+--------+--------+--------+-------------------+----------------+----------------------+\n" +
			    "| Options: " + formatString(getBytes(37), 75) + " |\n";
			    String thisDat;
			    while ((thisDat = getBytes(42)).length() > 0){
			    	thisInfo = thisInfo + "| " + formatString(thisDat, 84) + " |\n";
			    }
			    thisInfo = thisInfo +
			    "+---------------------------------------+----------------------------------------------+\n";
			}
		    return thisInfo;
	}

	public String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions){
		if (headerFlag && !conditions[0].equals(type)){
			return "";
		} else if(!conditions[3].equals("")){ // There is a SOURCE port restriction
			int prt1 = Integer.parseInt(conditions[3]);
			int prt2 = Integer.parseInt(conditions[4]);
			int thisprt = Integer.parseInt(thisLayer[0].trim());
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
			int thisprt = Integer.parseInt(thisLayer[1].trim());
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
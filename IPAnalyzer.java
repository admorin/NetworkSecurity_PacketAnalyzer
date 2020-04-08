import java.math.BigInteger;
import java.util.Arrays;

public class IPAnalyzer implements NetworkPacket{

	// Protocols:
    // 0x06 = TCP
    // 0x11 = UDP
    // 0x01 = ICMP

    private String packet = "";
    private String ogPacket = "";
    private String[] thisLayer = new String[15];
    private NetworkPacket nextPack;
    final String type = "ip";
    private boolean isFragmented = false;
    private String thisHeader;

    public IPAnalyzer(String packet){
    	this.packet = packet;
    	this.ogPacket = packet;
    }

	public void getInfo(PacketInfo packetInfo){
		String versANDihl = getBytes(1);
		thisLayer[0] = String.valueOf(versANDihl.charAt(0)); // Version
		thisLayer[1] = String.valueOf(versANDihl.charAt(1)); // IHL
		int headerlen = Integer.parseInt(thisLayer[1]);
		thisHeader = ogPacket.substring(0,headerlen*8);
		thisLayer[2] = getBytes(1); // DSCP/ECN
		thisLayer[3] = getBytes(2); // Total Length
		thisLayer[3] = String.valueOf(Integer.parseInt(thisLayer[3],16));
		thisLayer[4] = getBytes(2); // Identification
		thisLayer[5] = getBytes(2); // Offset
		thisLayer[12] = getFlags(thisLayer[5]); //Flags
		thisLayer[5] = removeFlags(thisLayer[5]);
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
		thisLayer[13] = packet;
		thisLayer[14] = ogPacket;
		packetInfo.setInfo("IP", thisLayer);
		if (thisLayer[12].equals("001") || Integer.parseInt(thisLayer[5]) > 0){
			this.isFragmented = true;
		} else {
	        if (thisLayer[7].equals("TCP ")){
				nextPack = new TCPAnalyzer(packet);
				nextPack.getInfo(packetInfo);
			} else if (thisLayer[7].equals("UDP ")){
				nextPack = new UDPAnalyzer(packet);
				nextPack.getInfo(packetInfo);
			} else if (thisLayer[7].equals("ICMP")){
				nextPack = new ICMPAnalyzer(packet);
				nextPack.getInfo(packetInfo);
			}
		}
		// thisLayer = {version, ihl, dscpecn, totallength, identification, offset, time2live, protocol, headerCS,
		//     srcIP, destIP, options};
	}

	public boolean isFragmented(){
		return this.isFragmented;
	}
    
	public String[] getFragInfo(){
		return thisLayer;
	}

	public String getID(){
		return thisLayer[4];
	}

	public String getBytes(int amount){
		String requested = packet.substring(0,(amount*2));
		packet = packet.substring(amount*2);
		return requested;
	}

	//The bits will be like this:
	//fffooooooooooooo, 3 flag, 13 offset
	//1110000000000000 = flag = 0xE000
	//0001111111111111 = offset = 0x1FFF

	public String getFlags(String hex){
		long val = Long.parseLong(hex, 16);
		long flags = (val & 0xE000) >> 13;
		return String.format("%3s", Long.toBinaryString(flags)).replace(' ', '0');
	}

	public String removeFlags(String hex){
        long val = Long.parseLong(hex, 16);
		long offset = (val & 0x1FFF);
		return Long.toString(offset);
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

	public boolean validateChecksum(){
		return calcChecksum(thisHeader);
	}

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

	public String getOptions(int headerlen){
		int bytes2get = (headerlen-5) * 4; // 4 bytes per line, and headerlen is how many lines are in options.
		String options = getBytes(bytes2get);
		return formatString(options, 49);
	}

	private String getReadable(){
		String totallength = formatString(thisLayer[3], 5);
		String offset = formatString(thisLayer[5], 5);
		String time2live = formatString(thisLayer[6], 3);
		String id = formatString(thisLayer[4], 4);
		String flags = formatString(thisLayer[12], 3);
		String thisInfo = 
			"+======================================================================================+\n" +
			"|                                     IP Header                                        |\n" +
			"+======================================================================================+\n" +
			"| Version: " + thisLayer[0] + "     | Header Length: " + thisLayer[1] + "     | DSCP/ECN: " + thisLayer[2] + "     | Total Length: " + totallength + "       |\n" + 
			"+----------------+--------+-------------+------------------+---------------------------+\n" +
			"| Identification: " + id + "    | Flags: " + flags + "  | Offset: " + offset +  "    | Time To Live: " + time2live + "         |\n" +
			"+-------------------------+-------------+------------------+---------------------------+\n" +
			"| Protocol: " + thisLayer[7] + "                        | Checksum: " + thisLayer[8] + "                             |\n" +
			"+---------------------------------------+----------------------------------------------+\n" +
			"| Source IP: " + thisLayer[9] + "            | Dest IP: " + thisLayer[10] + "                     |\n";
			if (thisLayer[11].equals("")){
				thisInfo = thisInfo + 
				"+---------------------------------------+----------------------------------------------+\n";
			} else {
				thisInfo = thisInfo +
				"+---------------------------------------+----------------------------------------------+\n" +
			    "| Options: " + thisLayer[11] + "                           |\n" +
			    "+---------------------------------------+----------------------------------------------+\n";
			}
			return thisInfo;
	}

	public String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions){
		if (conditions[0].equals("") || conditions[0].equals(type)){
			conditions[0] = "";
		}
		String nextHeader = nextPack.prettyPrint(headerFlag, andFlag, orFlag, conditions);

		if(nextHeader.equals("")){
			return "";
		} else {
			if(orFlag){ // Looking for a specific IP Address.
				if (conditions[1].equals(thisLayer[9].trim()) || conditions[2].equals(thisLayer[10].trim())){
					return getReadable() + nextHeader;
				} else {
					return "";
				}
			} else if (andFlag){
				if (conditions[1].equals(thisLayer[9].trim()) && conditions[2].equals(thisLayer[10].trim())){
					return getReadable() + nextHeader;
				} else {
					return "";
				}
			}
			return getReadable() + nextHeader;
		}

	}	
	
}
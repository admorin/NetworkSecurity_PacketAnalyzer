public class ICMPAnalyzer implements NetworkPacket {
	
	String packet = "";
    private String[] thisLayer = new String[3];
    final String type = "icmp";

    public ICMPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){
		thisLayer[0] = typeCode(getBytes(2)); // TypeANDCode
		thisLayer[1] = getBytes(2); // Checksum
		thisLayer[2] = getBytes(4); // Rest of Header
	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
		}
	}

	private String typeCode(String typeAndCode){
		int type = Integer.parseInt(typeAndCode.substring(0,2),16);
		int code = Integer.parseInt(typeAndCode.substring(2,4),16);
		String typeOut = "";
		String codeOut = "";
		switch (type) {
			case 0:
			    typeOut = "Echo Reply";
			    break;
		}
	}

	public String getBytes(int amount){
		String requested = packet.substring(0,(amount*2));
		packet = packet.substring(amount*2);
		return requested;
	}

	public String prettyPrint(boolean headerFlag, String typeFlag){

	}

}
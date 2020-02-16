public class TCPAnalyzer implements NetworkPacket {

	String packet = "";
    private String[] thisLayer = new String[12];
    final String type = "tcp";

    public TCPAnalyzer(String packet){
    	this.packet = packet;
    }

	public void getInfo(){

	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
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
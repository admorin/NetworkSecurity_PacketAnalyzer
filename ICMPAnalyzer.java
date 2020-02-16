public class ICMPAnalyzer implements NetworkPacket {
	
	String packet = "";
    private String[] thisLayer = new String[12];
    final String type = "icmp";

	public void getInfo(){

	}

	public boolean isType(String filter){
		if(filter.equals(type)){
			return true;
		} else {
			return false;
		}
	}

	public String prettyPrint(boolean headerFlag, String typeFlag){

	}

}
public interface NetworkPacket{
	boolean isType(String filter);
	void getInfo();
	String prettyPrint(String[] allInfo, boolean onlyHeader);
}
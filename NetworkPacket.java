public interface NetworkPacket{
	boolean isType(String filter);
	void getInfo();
	String prettyPrint(boolean headerFlag, String typeFlag);
}
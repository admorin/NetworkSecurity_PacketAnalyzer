public interface NetworkPacket{
	boolean isType(String filter);
	String[] getInfo();
	String prettyPrint(String[] allInfo, boolean onlyHeader);
}
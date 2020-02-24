public interface NetworkPacket{
	boolean isType(String filter);
	void getInfo();
	String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions);
}
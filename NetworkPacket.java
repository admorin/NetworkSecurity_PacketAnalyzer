public interface NetworkPacket{
	boolean isType(String filter);
	void getInfo(PacketInfo packetInfo);
	String prettyPrint(boolean headerFlag, boolean andFlag, boolean orFlag, String[] conditions);
	boolean isFragmented();
	String getID();
	String[] getFragInfo();
	boolean validateChecksum();
}
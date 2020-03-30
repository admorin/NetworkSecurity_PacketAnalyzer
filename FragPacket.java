import java.util.*;

public class FragPacket{

	private int sid;
	private String packet;
	private LinkedList<String> fragments;

	public FragPacket(LinkedList fragments, int sid, String packet){
		this.fragments = fragments;
		this.sid = sid;
		this.packet = packet;
	}

	public void addFragment(String fragment){
		fragments.add(fragment);
	}

	public int getSID(){
		return sid;
	}

	public String getPacket(){
		return packet;
	}

	public LinkedList getFragments(){
		return fragments;
	}
	
}
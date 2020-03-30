import java.util.LinkedList;
import java.math.BigInteger;

public class FragBuilder{

	private LinkedList<String[]> fragments = new LinkedList<String[]>();
	private LinkedList<String> fragStrings = new LinkedList<String>();
	private char[] builtPacket;
	private int sid;
	private boolean overlap = false;
	private boolean oversize = false;
	private String sourceIP;
	private String destIP;
	private String protocol;
	private String hexProtocol;
	private String identity;
	private int packetSize = -1;
	private boolean packetFinished = false;
	private String[] etherInfo;
	private String[] ipinfo;
	private String ttl = "";
	private String sourceIPHex;
	private String destIPHex;
	private String identityOUT = "1234";

	public FragBuilder(PacketInfo fragment){
		// System.out.println("\t\tFragment Created!");
		this.etherInfo = fragment.getLayerInfo("ETH");
		this.ipinfo = fragment.getLayerInfo("IP");
		this.sourceIP = ipinfo[9];
		this.destIP = ipinfo[10];
		this.sourceIPHex = ipToHex(sourceIP);
		this.destIPHex = ipToHex(destIP);
		this.protocol = ipinfo[7];
		this.hexProtocol = getHexProto(this.protocol);
		this.ttl = ttl + "80" + hexProtocol;
		this.identity = ipinfo[4];
		addFrag(ipinfo);
	}

	private String getHexProto(String protocol){
		switch(protocol){
			case("ICMP"):
			    return "01";
			case("TCP"):
			    return "06";
			case("UDP"):
			    return "11";
			default:
			    return "FF";
		}
	}

	public boolean addFrag(String[] fragment){
		fragments.add(fragment);
		fragStrings.add(fragment[14]);
		// System.out.println("\t\tFragment Added!");
		if(fragment[12].equals("000")){ // Final Fragment
			packetSize = 8 * Integer.parseInt(fragment[5]) + fragment[13].length()/2;
			if(packetSize > 65516){
				oversize = true;
			}
			builtPacket = new char[packetSize*2];
			for(int i = 0; i < packetSize*2; i++){
				builtPacket[i] = 'z';
			}
			if(packetSize == 0){
				System.out.println("ERROR: Packet Size is zero!");
			}
		}
		return attemptBuild();
	}

	public FragPacket getBuilt(){
		setSID();
		if(sid == 3){
			builtPacket = fragStrings.get(0).toCharArray();
			return new FragPacket(fragStrings, sid, new String(builtPacket));
		}
		String size = String.format("%4s", Integer.toHexString(packetSize + 20)).replace(' ', '0');
		String checksum = 
		    calcChecksum(new String[] {"4500", size, identityOUT, "0000", ttl, 
		    	    sourceIPHex.substring(0,4), sourceIPHex.substring(4,8), 
		    	    destIPHex.substring(0,4), destIPHex.substring(4,8)});

		String ethHead = etherInfo[0].replace(":", "") + 
		    etherInfo[1].replace(":", "") + etherInfo[2];

		String ipHead = ipinfo[0] + ipinfo[1] + "00" + size + identityOUT + 
		    "0000" + ttl + checksum + sourceIPHex + destIPHex;

		return new FragPacket(fragStrings, sid, ethHead + ipHead + new String(builtPacket));

		
	}

	public boolean isMatch(String[] otherFrag){
		if(otherFrag[9].equals(sourceIP) && otherFrag[10].equals(destIP)
			&& otherFrag[7].equals(protocol) && otherFrag[4].equals(identity)){
			return true;
		}
		return false;
	}

	private String ipToHex(String ip){
		String iphex = "";
		String[] ipsegments = ip.split("\\.");
		for(int i = 0; i < ipsegments.length; i++){
			iphex = iphex + Integer.toHexString(Integer.parseInt(ipsegments[i].replaceAll("\\s","")));
		}
		return iphex;
	}

	private String calcChecksum(String[] header){
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
		// System.out.println("Checksum: " + checksum);
		return checksum;

	}

	private boolean attemptBuild(){
		if(builtPacket != null){
			for(int i = 0; i < fragments.size(); i++){
				String[] thisfrag = fragments.get(i);
				// System.out.println(thisfrag[13]);
				int data = (Integer.parseInt(thisfrag[3]) - 20) * 2;
				int offset = Integer.parseInt(thisfrag[5]) * 8;
				if(thisfrag[13].length() != data){
					// System.err.println("ERROR: IP Length doesn't equal data!");
					// System.err.println("Length: " + thisfrag[13].length() + " - Data: " + data);
				} else {
					for(int j = 0; j < thisfrag[13].length(); j++){
						if(builtPacket[offset+j] != 'z'){
							overlap = true;
							data = data - 1;
						}
						builtPacket[2*offset+j] = thisfrag[13].charAt(j);
					}
					//System.out.println(data);
				}
				//System.out.println(new String(builtPacket));
			}
			fragments.clear();
			
			if(packetFilled()){
				packetFinished = true;
				System.out.println("Packet Finished.");
				return true;
			} else {
				// System.out.println("Still missing pieces!");
				return false;
			}
		}
		return false;
	}

	private void setSID(){
		if(packetFinished){
			if(overlap){
				sid = 2;
			} else {
				sid = 1;
			}
		} else {
			if(oversize){
				sid = 3;
			} else {
				sid = 4;
			}
		}
		
	}

	private boolean packetFilled(){
		if(new String(builtPacket).contains("z")){
			return false;
		} else {
			return true;
		}
	}
}
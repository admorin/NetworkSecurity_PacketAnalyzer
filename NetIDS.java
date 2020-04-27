import java.nio.ByteBuffer;
import java.util.*;
import java.io.*;

public class NetIDS{

	private LinkedList<Signature> signatures = new LinkedList<Signature>();
	
	public NetIDS(BufferedReader sigReader){
		importSignatures(sigReader);
	}

	private void importSignatures(BufferedReader sigReader){
		String thisLine = "";
		try{
			while((thisLine = sigReader.readLine()) != null){
				signatures.add(new Signature(thisLine.split(" ", 8)));
			}
		} catch(IOException e){
			System.out.println(e);
		}
	}

	public boolean screenPacket(PacketInfo info){
		IDSPacket packet = new IDSPacket();
		packet.setProtocol(info.getProtocols());
		packet.setIps(info.getIPs());
		packet.setPorts(info.getPorts());
		packet.setIPInfo(info.ipInts()); //TTL, TOS, ID, OFFSET
		packet.setIPOptions(info.getIPOpts());
		packet.setFragBits(info.getFragBits());
		packet.setPayload(info.getPayload());
		packet.setTCPInfo(info.tcpInts()); //flags, seq, ack
		packet.setICMPInfo(info.icmpInts()); //type, code
		packet.setOGPacket(info.getOGPacket());
		
		for(Signature sig : signatures){
			if(sig.checkMatch(packet)){
				return true;
			}
		}
		return false;
	}
}
import java.util.*;

public class IDSPacket{

	private String[] protocols;
	private String[] ips;
	private String[] ports;
	private String[] ipoptions;

	private int[] ipInfo;
	private int[] tcpInfo;
	private int[] icmpInfo;

	private String fragbits;
	private String payload;
	private String ogPacket;

	private int payloadSize;
	
	public void setProtocol(String[] protocols){
		this.protocols = protocols;
	}

	public List getProtocols(){
		return Arrays.asList(protocols);
	}

	public void setIps(String[] ips){
		this.ips = ips;
	}

	public String[] getIps(){
		return ips;
	}

	public void setPorts(String[] ports){
		this.ports = ports;
	}

	public int[] getPorts(){
		return new int[] {Integer.parseInt(ports[0].replaceAll(" ", "")), Integer.parseInt(ports[1].replaceAll(" ", ""))};
	}

	public void setIPOptions(String[] ipoptions){
		this.ipoptions = ipoptions;
	}

	public void setIPInfo(int[] ipInfo){
		this.ipInfo = ipInfo;
	}

	public int[] getIPInfo(){
		return ipInfo;
	}

	public void setTCPInfo(int[] tcpInfo){
		this.tcpInfo = tcpInfo;
	}

	public int[] getTCPInfo(){
		return tcpInfo;
	}

	public void setICMPInfo(int[] icmpInfo){
		this.icmpInfo = icmpInfo;
	}

	public int[] getICMPInfo(){
		return icmpInfo;
	}

	public void setFragBits(String fragbits){
		this.fragbits = fragbits;
	}

	public int getFragBits(){
		return Integer.parseInt(fragbits, 2);
	}

	public void setPayload(String payload){
		this.payload = payload;
		this.payloadSize = payload.length()/2;
	}

	public int getPayloadSize(){
		return payloadSize;
	}

	public String getPayload(){
		return payload;
	}

	public void setOGPacket(String ogPacket){
		this.ogPacket = ogPacket;
	}

	public String getOGPacket(){
		return ogPacket;
	}
}
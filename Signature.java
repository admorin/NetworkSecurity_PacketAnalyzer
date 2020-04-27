import java.io.*;
import java.util.*;
import java.nio.ByteBuffer;

public class Signature{
	
	private String action;
	private String protocol;
	private long cidrBlock1;
	private long mask1;
	private long cidrBlock2;
	private long mask2;
	private int port1;
	private int port2;
	private boolean bidirection;
	private String[] options;

	private String msg;
	private BufferedWriter wr;
	private int ttl = -1;
	private int tos = -1;
	private int id = -1;
	private int fragoffset = -1;
	private String ipoption;
	private int fragbits = -1; 
	private int fragmask = -1;
	private String fragbitsOP;
	private int dsize = -1;
	private int flags = -1;
	private int flagmask = -1;
	private String flagbitsOP;
	private int seq = -1;
	private int ack = -1;
	private int itype = -1;
	private int icode = -1;
	private String content;
	private boolean sameip;
	private int sid;


	public Signature(String[] sig){
        this.action = sig[0];
        this.protocol = sig[1].toUpperCase();
        long[] cidrInfo = parseCIDR(sig[2]);
        cidrBlock1 = cidrInfo[0];
        mask1 = cidrInfo[1];
        if(sig[3].equals("any")){
        	this.port1 = -1;
        } else {
            this.port1 = Integer.parseInt(sig[3]);
        }
        this.bidirection = sig[4].equals("<>");
        cidrInfo = parseCIDR(sig[5]);
        cidrBlock2 = cidrInfo[0];
        mask2 = cidrInfo[1];
        if(sig[6].equals("any")){
        	this.port2 = -1;
        } else {
            this.port2 = Integer.parseInt(sig[6]);
        }
        if(sig.length == 8){
        	if(sig[7].contains("msg:")){
        		String[] tempOpts = sig[7].replaceAll("[()]", "").split(";");
        		for(String opt : tempOpts){
        			String[] optPair = opt.split(":");
        			if(optPair[0].equals("msg")){
        				msg = optPair[1].replace("\"", "");
        				if(msg.charAt(0) == ' '){
        					msg = msg.substring(1);
        				}
        				break;
        			}
        		}
        	}
        	this.options = sig[7].replaceAll("[() ]", "").split(";");
        	parseOptions();
        }
	}

	private void parseOptions(){
		for(int i = 0; i < options.length; i++){
			String[] key_arg = options[i].split(":");
			if(key_arg[0].equals("msg")){
				System.out.println(msg);
				// this.msg = key_arg[1];
			} else if(key_arg[0].equals("logto")){
				try{
                    File file = new File(key_arg[1].replace("\"", ""));
                    if (!file.exists()) {
                    	System.out.println("File doesn't exist...");
                        file.createNewFile();
                    }
                    FileWriter fw = new FileWriter(file, true);
                    wr = new BufferedWriter(fw);
                    System.out.println("\t\tSUCCESS: Logging to: " + key_arg[1]);
                } catch (IOException e){
                    System.out.println("\t\tERROR: Could not load file: " + key_arg[1]);
                }
			} else if(key_arg[0].equals("ttl")){
				this.ttl = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("tos")){
				this.tos = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("id")){
				this.id = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("fragoffset")){
				this.fragoffset = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("ipoption")){
				this.ipoption = key_arg[1];
			} else if(key_arg[0].equals("fragbits")){
				String strBits = key_arg[1];
			    fragmask = 7;
				fragbits = 0;
				if(strBits.contains("R")){
					fragbits = 1;
				} 
				fragbits = fragbits << 1;
				if(strBits.contains("D")){
					fragbits += 1;
				}
				fragbits = fragbits << 1;
				if(strBits.contains("M")){
					fragbits += 1;
				}
				if(strBits.contains("+")){
					fragmask = fragbits;
					fragbitsOP = "+";
				} else if(strBits.contains("*")){
					fragmask = fragbits;
					fragbitsOP = "*";
				} else if(strBits.contains("!")){
					fragmask = fragbits;
					fragbitsOP = "!";
				}
			} else if(key_arg[0].equals("dsize")){
				this.dsize = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("flags")){
				String strFlags = key_arg[1];
				flagmask = 255;
				flags = 0;
				if(strFlags.contains("E")){
					flags = 1;
				} 
				flags = flags << 1;
				if(strFlags.contains("C")){
					flags += 1;
				}
				flags = flags << 1;
				if(strFlags.contains("U")){
					flags += 1;
				}
				flags = flags << 1;
				if(strFlags.contains("A")){
					flags += 1;
				}
				flags = flags << 1;
				if(strFlags.contains("P")){
					flags += 1;
				}
				flags = flags << 1;
				if(strFlags.contains("R")){
					flags += 1;
				}
				flags = flags << 1;
				if(strFlags.contains("S")){
					flags += 1;
				}
				flags = flags << 1;
				if(strFlags.contains("F")){
					flags += 1;
				}
				if(strFlags.contains("0")){
					flags = 0;
				}
				if(strFlags.contains("+")){
					flagmask = flags;
					flagbitsOP = "+";
				} else if(strFlags.contains("*")){
					flagmask = flags;
					flagbitsOP = "*";
				} else if(strFlags.contains("!")){
					flagmask = flags;
					flagbitsOP = "!";
				}
			} else if(key_arg[0].equals("seq")){
				this.seq = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("ack")){
				this.ack = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("itype")){
				this.itype = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("icode")){
				this.icode = Integer.parseInt(key_arg[1]);
			} else if(key_arg[0].equals("content")){
				this.content = key_arg[1];
			} else if(key_arg[0].equals("sameip")){
				this.sameip = Boolean.parseBoolean(key_arg[1]);
			} else if(key_arg[0].equals("sid")){
				this.sid = Integer.parseInt(key_arg[1]);
			} else {
				System.out.println("ERROR: Unknown Sig Option: " + key_arg[0]);
			}
		}
	}

	public boolean checkMatch(IDSPacket packet){
		if(packet.getProtocols().contains(protocol)){
			if(checkAddressMatch(bidirection, packet)){
				return checkOptions(packet);
			} else {
				// System.out.println("Sig Failed IP/Port Match.");
				return false;
			}
		} else {
			// System.out.println("Sig Failed Protocol Match.");
			return false;
		}
	}

	private long[] parseCIDR(String ip){
		long thisBlock = 0;
		long thisMask = 0;
		if(ip.equals("any")){
			return new long[] {0L, 0L};
		} else {
			String[] blockInfo = ip.split("/");
			String[] addressBlocks = blockInfo[0].split("\\.");
			for(int i = 0; i < 4; i++){
				thisBlock += Long.parseLong(addressBlocks[i]);
				if(i != 3){
					thisBlock = thisBlock << 8;
				}
			}
			thisMask = ~(4294967295L >> Long.parseLong(blockInfo[1])) & 4294967295L;
		}
		return new long[] {thisBlock, thisMask};
	}

	private boolean checkOptions(IDSPacket packet){
		int[] ipInfo = packet.getIPInfo(); //TTL, TOS, ID, OFFSET
		if(ttl != -1 && ipInfo[0] != ttl){
			return false;
		}
		if(tos != -1 && ipInfo[1] != tos){
			return false;
		}
		if(id != -1 && ipInfo[2] != id){
			return false;
		}
		if(fragoffset != -1 && ipInfo[3] != fragoffset){
			return false;
		}
		//TODO: IP Options check.
		if(fragbits != -1 && !bitCheck(packet.getFragBits(), fragbitsOP, fragmask, fragbits)){
			return false;
		}
		if(dsize != -1 && dsize != packet.getPayloadSize()){
			return false;
		}
		int[] tcpInfo = packet.getTCPInfo();
		if(flags != -1 && !bitCheck(tcpInfo[0], flagbitsOP, flagmask, flags)){
			return false;
		}
		if(seq != -1 && tcpInfo[1] != seq){
			return false;
		}
		if(ack != -1 && tcpInfo[2] != ack){
			return false;
		}
		int[] icmpInfo = packet.getICMPInfo();
		if(itype != -1 && icmpInfo[0] != itype){
			return false;
		}
		if(icode != -1 && icmpInfo[1] != icode){
			return false;
		}
		if(content != null && !packet.getPayload().replaceAll("\\s+","").contains(content)){
			return false;
		}
		if(sameip && packet.getIps()[0] != packet.getIps()[1]){
			return false;
		}
		respond(packet);
		return true;
	}

	private boolean bitCheck(int packetBits, String oper, int mask, int sigBits){
		if(oper != null){
			if(oper.equals("+")){
				return (packetBits & mask) == sigBits;
			} else if(oper.equals("*")){
				return (packetBits & mask) > 0;
			} else { // "!"
				return (packetBits & mask) == 0;
			}
		} else {
			return (packetBits & mask) == sigBits;
		}
	}

	private void respond(IDSPacket packet){
		if(wr == null){
			if(msg != null){
				System.out.println("\tIDS ALERT: " + msg);
			}
			return;
		} else {
			try{
				if(msg != null){
					wr.write(msg);
				}
				wr.write(formatOGPacket(packet.getOGPacket()));
				wr.flush();
			} catch (IOException e){
				System.out.println("ERROR: Cannot write packet to log.");
			}
			
		}
	}

	private String formatOGPacket(String ogPacket){
		String formatted = "";
		for(int i = 0; i < ogPacket.length()/2; i++){
			if(i%16 == 0){
				formatted += "\n";
			}
			formatted += ogPacket.substring(i*2, i*2+2) + " ";
		}
		return formatted + "\n\n";
	}

	private boolean checkAddressMatch(boolean bidirection, IDSPacket packet){
		boolean match = (checkCIDR(packet.getIps()[0], mask1, cidrBlock1) && 
	                     checkPort(packet.getPorts()[0], port1) &&
		                 checkCIDR(packet.getIps()[1], mask2, cidrBlock2) &&
		                 checkPort(packet.getPorts()[1], port2));
		if(bidirection){
			match = match && (checkCIDR(packet.getIps()[1], mask1, cidrBlock1) && 
			                  checkPort(packet.getPorts()[1], port1) &&
			                  checkCIDR(packet.getIps()[0], mask2, cidrBlock2) &&
			                  checkPort(packet.getPorts()[0], port2));
		}
		return match;
	}

	private boolean checkCIDR(String ip, long mask, long cidrBlock){
		if(cidrBlock == 0 && mask == 0){
			return true;
		}
		long address = 0;
		String[] splitAddr = ip.split("\\.");
		for(int i = 0; i < 4; i++){
			address += Long.parseLong(splitAddr[i].replaceAll(" ", ""));
			if(i != 3){
				address = address << 8;
			}
		}
		return cidrBlock == (address & mask);
	}

	private boolean checkPort(int port, int sigPort){
		if (sigPort == -1){
			return true;
		} else {
			return port == sigPort;
		}
	}
}
























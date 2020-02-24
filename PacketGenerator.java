import java.nio.ByteBuffer;
import java.util.Scanner;
import java.io.*;

public class PacketGenerator
{

	static Scanner scan = new Scanner(System.in);
	static BufferedReader br;

	public static void main(String[] args) {
		if(args.length > 0){
			String inputFile = args[0];
            System.out.println("\tAttempting to open file: " + inputFile + "...");
            try{
                FileReader fr=new FileReader(inputFile);    
                br=new BufferedReader(fr);
                System.out.println("\t\tSUCCESS: Reading packets from: " + inputFile);
            } catch (IOException e){
                System.out.println("\t\tERROR: Could not load file. Will read from adapters instead.");
                return;
            }
		} else {
			System.out.println("\tERROR: No file to read from.");
			return;
		}
        SimplePacketDriver driver=new SimplePacketDriver();
		//Get adapter names and print info
        String[] adapters=driver.getAdapterNames();
        System.out.println("Number of adapters: "+adapters.length);
        for (int i=0; i< adapters.length; i++) System.out.println(i+1 + ") \tDevice Name: "+adapters[i]);
        System.out.println("Please choose your device (Enter row #):");
        int choice = scan.nextInt();
        //Open first found adapter (usually first Ethernet card found)
        if (driver.openAdapter(adapters[choice-1])) System.out.println("Adapter is open: "+adapters[choice-1]);
        //TODO if driver choice is bad, catch error here.
        int counter = 1;
        while(true){
        	System.out.println(counter);
        	counter++;
        	String hexPacket = readPacketFromFile();
        	if(hexPacket == null){
        		return;
        	}
        	byte[] packet = hexStringToByteArray(hexPacket);
	        //Wrap it into a ByteBuffer
	        ByteBuffer Packet=ByteBuffer.wrap(packet);
	        //Print packet summary
	        System.out.println("Packet: "+Packet+" with capacity: "+Packet.capacity());
	        // System.out.println(driver.byteArrayToString(packet));
	        //Send the same packet now (change headers)
	        // for (int i=0; i< 12; i++) packet[i]=1; //Destination
	        // for (int i=0; i< packet.length; i++) packet[i]=1; //Source
	        // packet[12]=9; packet[13]=10; //Make up a type
			//Send packet
	        if (!driver.sendPacket(packet)) System.out.println("Error sending packet!");


	        }

        }
		

        private static String readPacketFromFile(){
        String thisPacket = "";
        String thisLine = "";
            try{
                while ((thisLine = br.readLine()) != null) {
                    if (thisLine.equals("")){
                        if (!thisPacket.equals("")){
                            return thisPacket;
                        } else {
                            continue;
                        }
                    }
                    thisPacket = thisPacket + thisLine.replaceAll("\\s+", "");
                }
                return null;
            } catch (IOException e){
                System.out.println(e);
                return null;
            }
    }

        public static byte[] hex2Byte(String hex) {
		    byte[] packet = new byte[hex.length() / 2];
		    for (int i = 0; i < hex.length(); i += 2) {
		        packet[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i+1), 16));
		    }
		    return packet;
		}
 
}

import java.nio.ByteBuffer;
import java.util.Scanner;
import java.io.*;

public class PacketSniffer {

    // Protocol id's.
    final int ethernet = 1;
    final int peer2peer = 2;
    final int loopback = 3;


    static BufferedReader br;
    static BufferedWriter wr;
    static SimplePacketDriver driver;
    static int linecount = 0;

    // CL Flags
    static int counting = -1;
    static String inputFile = "";
    static String outputFile = "";
    static String filter = ""; // eth, arp, ip, icmp, tcp, or udp
    static boolean headers = false;



    public static void main(String[] args) {
        parseFlags(args);
        int packetCount = 0;
        if (inputFile.equals("")){ //Reading from driver, so setup the driver.
            driver=new SimplePacketDriver();
            Scanner scan = new Scanner(System.in);
            //Get adapter names and print info
            String[] adapters=driver.getAdapterNames();
            System.out.println("Number of adapters: "+adapters.length);
            for (int i=0; i< adapters.length; i++) System.out.println(i+1 + ") \tDevice Name: "+adapters[i]);
            System.out.println("Please choose your device (Enter row #):");
            int choice = scan.nextInt();
            //Open first found adapter (usually first Ethernet card found)
            if (driver.openAdapter(adapters[choice-1])) System.out.println("Adapter is open: "+adapters[choice-1]);
            //TODO if driver choice is bad, catch error here.
        }
        while(true){
            String hexPacket = "";
            if(inputFile.equals("")){// Reading from driver.
                byte[] packet = readPacketFromDriver(driver);
                ByteBuffer Packet=ByteBuffer.wrap(packet);
                String packetInfo = driver.byteArrayToString(packet);
                hexPacket = convertToHexString(packet, driver);
            } else {
                hexPacket = readPacketFromFile();
                // System.out.println(linecount);
                if (hexPacket == null){
                    flush(wr);
                    return;
                }
            }
            EthernetAnalyzer analyze = new EthernetAnalyzer(hexPacket);
            String[] info = analyze.getInfo();
            if(info != null && analyze.isType(filter)){
                packetCount++;
                if (outputFile.equals("")){
                    System.out.println(info);
                } else {
                    try{
                        wr.write(info);
                    } catch (IOException e){
                        System.out.println("ERROR: " + e);
                    }
                }
            }
            if (packetCount == counting){
                flush(wr);
                break;
            }
        }
    }

    static byte[] readPacketFromDriver(SimplePacketDriver driver){
        return driver.readPacket();
    }

    static void flush(BufferedWriter wr){
        if (outputFile.equals("")){
            return;
        }
        try{
            wr.close();
        } catch (IOException e){
            System.out.println("ERROR FLUSHING.");
        }
    }

    static String readPacketFromFile(){
        String thisPacket = "";
        String thisLine = "";
            try{
                while ((thisLine = br.readLine()) != null) {
                    linecount++;
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

    static String convertToHexString(byte[] packet, SimplePacketDriver driver){
        String hexString = "";
        for (int i = 0; i < packet.length; i++){
            hexString = hexString + driver.byteToHex(packet[i]);
        }
        return hexString;
    }

    static void parseFlags(String[] args){
        if (args.length > 0){
            System.out.println("\nFLAGS:\n");
            for (int i = 0; i < args.length; i++){
                String thisFlag = args[i];
                if (thisFlag.equals("-c")){
                    counting = Integer.parseInt(args[i+1]);
                    i++;
                    System.out.println("\tCapturing " + counting + " packets.");
                } else if (thisFlag.equals("-r")){
                    inputFile = args[i+1];
                    System.out.println("\tAttempting to open file: " + inputFile + "...");
                    i++;
                    try{
                        FileReader fr=new FileReader(inputFile);    
                        br=new BufferedReader(fr);
                        System.out.println("\t\tSUCCESS: Reading packets from: " + inputFile);
                    } catch (IOException e){
                        System.out.println("\t\tERROR: Could not load file. Will read from adapters instead.");
                        inputFile = "";
                    }
                } else if (thisFlag.equals("-o")){
                    outputFile = args[i+1];
                    System.out.println("\tAttempting to open file: " + outputFile + "...");
                    i++;
                    try{
                        File file = new File(outputFile);
                        if (!file.exists()) {
                            file.createNewFile();
                        }
                        FileWriter fw = new FileWriter(file);
                        wr = new BufferedWriter(fw);
                        System.out.println("\t\tSUCCESS: Writing packets to: " + outputFile);
                    } catch (IOException e){
                        System.out.println("\t\tERROR: Could not load file. Will output to terminal instead.");
                        outputFile = "";
                    }

                } else if (thisFlag.equals("-t")){
                    filter = args[i+1];
                    i++;
                    System.out.println("\tFiltering packets of type: " + filter);
                } else if (thisFlag.equals("-h")){
                    if (filter.equals("")){
                        System.out.println("No type selected, printing all headers.");
                    } else {
                        headers = true;
                        System.out.println("\tPrinting only header info of type: " + filter);
                    }
                }
            }
            System.out.println("\nEND OF FLAGS\n");
        }
    }
}

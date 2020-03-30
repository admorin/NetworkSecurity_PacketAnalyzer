import java.nio.ByteBuffer;
import java.util.*;
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
    static int packetCount = 0;

    // CL Flags
    static int counting = -1;
    static String inputFile = "";
    static String outputFile = "";
    static String filter = ""; // eth, arp, ip, icmp, tcp, or udp
    static boolean headF = false;
    static String sadd = "";
    static String dadd = "";
    static String sprt1 = "";
    static String sprt2 = "";
    static String dprt1 = "";
    static String dprt2 = "";
    static boolean andF = false;
    static boolean orF = false;
    private static String[] flags = new String [7];


    private static LinkedList<PacketInfo> fragments = new LinkedList<PacketInfo>();
    private static LinkedList<FragPacket> builtPackets = new LinkedList<FragPacket>();
    private static LinkedList<FragPacket> readyPackets = new LinkedList<FragPacket>();
    private static FragManager fragManager = new FragManager(fragments, builtPackets);

    // private static HashMap<String, LinkedList> fragmap = new HashMap<String, LinkedList>();
    // private static HashMap<String, Thread> timemap = new HashMap<String, Thread>();


    public static void main(String[] args) {
        parseFlags(args);
        flags[0] = filter;
        flags[1] = sadd;
        flags[2] = dadd;
        flags[3] = sprt1;
        flags[4] = sprt2;
        flags[5] = dprt1;
        flags[6] = dprt2;
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
        //Start the Fragment Manager.
        Thread fragThread = new Thread(fragManager);
        fragThread.start();
        boolean running = true;
        while(running){
            // This packet starts empty.
            String hexPacket = "";

            // If reading from driver....
            if(inputFile.equals("")){
                byte[] packet = readPacketFromDriver(driver);
                ByteBuffer Packet=ByteBuffer.wrap(packet);
                // String packetInfo = driver.byteArrayToString(packet);
                hexPacket = convertToHexString(packet, driver);
            } // If reading from a file...
            else {
                hexPacket = readPacketFromFile();
                // System.out.println(linecount);
                if (hexPacket == null){
                    break;
                }
            }
            // Create an ethernet analyzer with this packet.
            EthernetAnalyzer analyze = new EthernetAnalyzer(hexPacket);
            PacketInfo packetInfo = new PacketInfo();
            analyze.getInfo(packetInfo);
            //Fragmentation ------------------------------------------v
            if (analyze.isFragmented()){
                // System.out.println("Fragmented!");
                synchronized(fragments){
                    // System.out.println("Adding to buffer...");
                    fragments.add(packetInfo);
                }
            } //------------------------------------------------------^
            else {
                retrieveInfo(analyze);
            }
            if (packetCount == counting){
                break;
            }
            synchronized(builtPackets){
                for(int i = 0; i < builtPackets.size(); i++){
                    readyPackets.add(builtPackets.get(i));
                }
                builtPackets.clear();
            }
            for(int i = 0; i < readyPackets.size(); i++){
                buildAndAnalyze(readyPackets.get(i));
            }
            readyPackets.clear();
        }
        // Scanner scan = new Scanner(System.in);
        // System.out.println("Press enter to continue...");
        // scan.nextLine();
        System.out.println("Killing Frag Manager...");
        if (fragManager != null){
            fragManager.terminate();
            try{
                fragThread.join();
                System.out.println("Frag Manager Killed Successfully.");
            } catch (InterruptedException e){
                System.out.println("Error Killing Frag Manager!");
            }
            System.out.println("Checking for remaining built packets...");
            synchronized(builtPackets){
                for(int i = 0; i < builtPackets.size(); i++){
                    readyPackets.add(builtPackets.get(i));
                }
                builtPackets.clear();
            }
            for(int i = 0; i < readyPackets.size(); i++){
                if (packetCount == counting){
                    break;
                }
                buildAndAnalyze(readyPackets.get(i));
                packetCount++;
            }
            readyPackets.clear();
            flush(wr);
            System.out.println("Sniffer closing...");
        }
    }

    static void buildAndAnalyze(FragPacket rebuiltPacket){
        System.out.println("Analyzing rebuilt packets...");
        EthernetAnalyzer analyze = new EthernetAnalyzer(rebuiltPacket.getPacket());
        PacketInfo packetInfo = new PacketInfo();
        analyze.getInfo(packetInfo);
        retrieveInfo(analyze);
    }

    static void retrieveInfo(EthernetAnalyzer fullPacket){
        String prettyInfo = fullPacket.prettyPrint(headF, andF, orF, flags);
        if (!prettyInfo.equals("")){
            packetCount++;
            if (outputFile.equals("")){
                System.out.println(prettyInfo);
            } else {
                try{
                    wr.write(prettyInfo);
                } catch (IOException e){
                    System.out.println("ERROR(RI): " + e);
                }
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
                        headF = true;
                        System.out.println("\tPrinting only header info of type: " + filter);
                    }
                } else if (thisFlag.equals("-src")){
                    sadd = args[i+1];
                    orF = true;
                    i++;
                    System.out.println("\tFiltering only packets from IP Address: " + sadd);
                } else if (thisFlag.equals("-dst")){
                    dadd = args[i+1];
                    orF = true;
                    i++;
                    System.out.println("\tFiltering only packets to IP Address: " + dadd);
                } else if (thisFlag.equals("-sord")){
                    sadd = args[i+1];
                    dadd = args[i+2];
                    orF = true;
                    i += 2;
                    System.out.println("\tFiltering packets from IP Address: " + sadd + "\n\tor to IP Address: " + dadd);
                } else if (thisFlag.equals("-sandd")){
                    sadd = args[i+1];
                    dadd = args[i+2];
                    andF = true;
                    i += 2;
                    System.out.println("\tFiltering packets from IP Address: " + sadd + "\n\tand to IP Address: " + dadd);
                } else if (thisFlag.equals("-sport")){
                    sprt1 = args[i+1];
                    sprt2 = args[i+2];
                    i += 2;
                    System.out.println("\tFiltering packets originating from port range: " + sprt1 + " - " + sprt2);
                } else if (thisFlag.equals("-dport")){
                    dprt1 = args[i+1];
                    dprt2 = args[i+2];
                    i += 2;
                    System.out.println("\tFiltering packets directed to port range: " + dprt1 + " - " + dprt2);
                } else {
                    System.out.println("ERROR: Unsure of what this flag is: " + thisFlag);
                }
            }
            System.out.println("\nEND OF FLAGS\n");
        }
    }
}

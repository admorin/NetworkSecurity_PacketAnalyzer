import java.util.*;

public class FragManager implements Runnable{

	private volatile boolean running = true;
	private LinkedList<PacketInfo> newFragments;
	private LinkedList<FragPacket> builtPackets;

	private LinkedList<PacketInfo> localFragments = new LinkedList<PacketInfo>();
	private LinkedList<FragBuilder> builders = new LinkedList<FragBuilder>();

	public FragManager(LinkedList newFragments, LinkedList builtPackets){
		this.newFragments = newFragments;
		this.builtPackets = builtPackets;
	}

	public void terminate(){
		running = false;
	}

    @Override
    public void run(){
    	System.out.println("\tFrag Manager Running...");
    	while(running){
    		System.out.println("\tChecking for new fragments...");
    		checkBuffer();
    		try{
                Thread.sleep(1000);
            }catch (InterruptedException e){
            	System.out.println("ERROR: FragManager!");
            }
    	}
    	checkBuffer();
    }

    private void checkBuffer(){
    	synchronized(newFragments){
    		for(int i = 0; i < newFragments.size(); i++){
    			localFragments.add(newFragments.get(i));
    		}
    		newFragments.clear();
    	}
    	for(int i = 0; i < localFragments.size(); i++){
    		sortFragments(localFragments.get(i));
    	}
    	localFragments.clear();

    }

    private void sortFragments(PacketInfo fragInfo){
    	// System.out.println("\tSorting...");
    	String[] fragment = fragInfo.getLayerInfo("IP");
    	for(int i = 0; i < builders.size(); i++){
    		if(builders.get(i).isMatch(fragment)){
    			if(builders.get(i).addFrag(fragment)){
    				synchronized(builtPackets){
    					System.out.println("\tAdding rebuilt packets.");
    					builtPackets.add(builders.get(i).getBuilt());
    				}
    				builders.remove(i);
    			}
    			return;
    		}
    	}
    	builders.add(new FragBuilder(fragInfo));
    }
	
}
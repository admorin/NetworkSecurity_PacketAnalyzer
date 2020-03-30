import java.util.*;

public class FragManager implements Runnable{

	private volatile boolean running = true;
	private LinkedList<PacketInfo> newFragments;
	private LinkedList<FragPacket> builtPackets;

	private LinkedList<PacketInfo> localFragments = new LinkedList<PacketInfo>();
	private LinkedList<FragBuilder> builders = new LinkedList<FragBuilder>();
	private HashMap<FragBuilder, FragTimer> timerMap = new HashMap<FragBuilder, FragTimer>();

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
    		cleanBuilders();
    		try{
                Thread.sleep(1000);
            }catch (InterruptedException e){
            	System.out.println("ERROR: FragManager!");
            }
    	}
    	checkBuffer();
    	cleanBuilders();
		killBuilders();
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
    				System.out.println("\tBuilt new packet........");
    				synchronized(builtPackets){
    					System.out.println("\tAdding rebuilt packets.");
    					builtPackets.add(builders.get(i).getBuilt());
    				}
    				FragBuilder thisBuilder = builders.get(i);
    				timerMap.get(thisBuilder).terminate();
    				try{
		                timerMap.get(thisBuilder).t.join();
		                System.out.println("Frag Timer Killed Successfully.");
		            } catch (InterruptedException e){
		                System.out.println("Error Killing Frag Timer!");
		            }
    				timerMap.remove(thisBuilder);
    				builders.remove(i);
    			}
    			return;
    		}
    	}
    	FragBuilder newBuilder = new FragBuilder(fragInfo);
    	builders.add(newBuilder);
    	timerMap.put(newBuilder, new FragTimer(5));

    }

    private void cleanBuilders(){
	    Iterator iter = timerMap.entrySet().iterator();
	    while (iter.hasNext()) {
	        Map.Entry<FragBuilder, FragTimer> pair = (Map.Entry)iter.next();
	        if(pair.getValue().timedOut()){
	        	iter.remove();
	        }
	    }
    }

    private void killBuilders(){
    	System.out.println("Killing Builders...");
    	for(Map.Entry<FragBuilder, FragTimer> entry : timerMap.entrySet()){
    		entry.getValue().terminate();
	    }
    }
	
}
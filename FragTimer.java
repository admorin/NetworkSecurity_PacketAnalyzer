import java.util.*;

public class FragTimer implements Runnable{

	private int duration;
	private boolean running = true;
	private boolean timeout = false;
	Thread t;

	public FragTimer(int duration){
		this.duration = duration;
		this.t = new Thread(this);
		t.start();
	}

	public void terminate(){
		running = false;
	}

	public boolean timedOut(){
		return timeout;
	}

    @Override
    public void run(){
    	for (int i = duration; i >= 0; i--) {
    		if(!running){
    			// System.out.println("Thread Interrupted!");
    			break;
    		}
            try{
                Thread.sleep(1000);
            }catch (InterruptedException e){
            	System.out.println("ERROR: FragTimer!");
            }
        }
        if(running){
        	timeout = true;
        	// System.out.println("Thread Timed Out!");
        }
        
    }
}
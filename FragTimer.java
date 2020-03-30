import java.util.*;

public class FragTimer implements Runnable{

	private int duration;

	public FragTimer(int duration){
		this.duration = duration;
	}

    @Override
    public void run(){
    	for (int i = duration; i >= 0; i--) {
            try{
                Thread.sleep(1000);
            }catch (InterruptedException e){
            	System.out.println("ERROR: FragTimer!");
            }
            System.out.println(i);
        }
    }
}
import java.util.Calendar;

public class Timer {
	private static long startTime, endTime;
	
	public static void startTimer() {
		startTime = Calendar.getInstance().getTimeInMillis();
	}
	
	public static long stopTimer() {
		endTime = Calendar.getInstance().getTimeInMillis();
		
		return endTime - startTime;
	}
}

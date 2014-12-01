import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;


public class Driver {

	List<String> usernames=new ArrayList<String>();
	List<String>dictionary;
	private static final String DICTIONARY_FILENAME="500-worst-passwords.txt";
	Map<String, String> userWithPassword=new HashMap<String, String>();
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Driver driver=new Driver();
		driver.getRawData();
		//loadDictionary();
		//crackPasswords();
		//displayResults();

	}
	public void getRawData()
	{
		dictionary=getDictionary(DICTIONARY_FILENAME);//TODO allow user to specify file name
		
		List<String> passwdEntries=readLinesFromFile("files/passwd");
		for(String entry:passwdEntries )//each entry in passwd
		{
			if(entry.contains(":"))
			{
				//System.out.println(entry);
				String [] parts=entry.split(":");
				if(Integer.parseInt(parts[2])>1000)
					usernames.add(parts[0]);
			}
		}
		
		List<String> shadowEntries=readLinesFromFile("files/shadow");//or are we not supposed to see the hashes?
		
		for(String entry:shadowEntries )
		{
			
			if(entry.contains(":"))//because the scanner reads extra blank lines for some reason
			{
				
				String [] parts=entry.split(":");
				//System.out.println(entry);
				//System.out.println(parts[0]);
				if (usernames.contains(parts[0]))
					userWithPassword.put(parts[0],parts[1]);
			}
		}
		for(Map.Entry e: userWithPassword.entrySet())
		{
			System.out.println(e.getKey()+":"+e.getValue());
		}
	}
	
	/*public void parseShadowEntry(String entry)
	{
		String [] parts=entry.split(":");
		String username=parts[0];
		String passwordhash=parts[1];
	}*/
	
	/*public void parsePasswdEntry(String entry)
	{
		String [] parts=entry.split(":");
		String username=parts[0];
		String userid=parts[2];
	}*/
	public List<String> readLinesFromFile(String filepath)
	{
		ArrayList<String> lines = new ArrayList<String>();
		Scanner s=null;
		try {
			
			s = new Scanner(new File(filepath)).useDelimiter("\n");
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		while (s.hasNext()){
		    lines.add(s.next());
		}
		s.close();
		return lines;
	}
	public List<String> getDictionary(String filename)
	{
		return readLinesFromFile("dict/"+filename);
	}
	
	public void parseHash(String hash)
	{
		String[] hashParts=hash.split("$");
		int algorithmID=Integer.parseInt(hashParts[0]);//or hashParts[1] since the string starts with $?
		String salt=hashParts[1];
		String actualHash=hashParts[2];
	}
	
}

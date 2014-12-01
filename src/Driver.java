import java.io.File;
import java.io.FileNotFoundException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;


public class Driver {

	
	List<String> usernames=new ArrayList<String>();
	List<String>dictionary;
	private static final String DICTIONARY_FILENAME="500-worst-passwords.txt";
	List<AccountDetails> accounts = new ArrayList<AccountDetails>();
	Map<String, String> userPassMap = new HashMap<String, String>(); // map (user, pass)
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Driver driver=new Driver();
		
		// ask for file inputs for passwd file, shadow file and dictionary file
		driver.getRawData();
		driver.loadDictionary(DICTIONARY_FILENAME);
		
		Collections.reverse(driver.dictionary);
		
		System.out.println("Timer start!\n");
		Timer.startTimer();
		
		driver.crackPasswords();
		driver.displayResults();
		
		System.out.println("\nTotal time: " + Timer.stopTimer() + "ms");
	}
	
	private void displayResults() {
		int c = 1;
		
		System.out.println("Accounts found: " + userPassMap.entrySet().size());
		for (Entry<String, String> n : userPassMap.entrySet()) {
			System.out.println("Enum " + c++);
			System.out.println("Username: " + n.getKey());
			System.out.println("Password: " + n.getValue());
		}
		
	}

	public void getRawData()
	{
		List<String> passwdEntries=readLinesFromFile("files/passwd");
		for(String entry:passwdEntries )//each entry in passwd
		{
				String [] parts=entry.split(":");
				if(Integer.parseInt(parts[2])>1000)
					usernames.add(parts[0]);
		}
		
		List<String> shadowEntries=readLinesFromFile("files/shadow");//or are we not supposed to see the hashes?
		for(String entry:shadowEntries )
		{
			String [] parts=entry.split(":");
			if (usernames.contains(parts[0]))
				if (parts[1].length() > 1)
					accounts.add(new AccountDetails(parts[0],parts[1]));
		}
	}
	
	public List<String> readLinesFromFile(String filepath)
	{
		ArrayList<String> lines = new ArrayList<String>();
		Scanner s=null;
		try {
			s = new Scanner(new File(filepath));//.useDelimiter(System.getProperty("line.separator"));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		while (s.hasNextLine()){
			String next=s.nextLine();
			//next=next.substring(0, next.indexOf('\n'));
			if (next.trim().length() != 0)
				lines.add(next);
		}
		s.close();
		return lines;
	}
	
	public void loadDictionary(String filename)
	{
		dictionary = readLinesFromFile("dict/"+filename);
	}
	
	public void crackPasswords() {
		for (AccountDetails a : accounts) {
			String password=a.findPass(dictionary);
			if (password != null)
				userPassMap.put(a.username, password);
		}
	}
}

class AccountDetails {
	String username;
	String hashword;
	String salt;
	
	public AccountDetails(String user, String code) {
		username = user;
		
		String[] parts = code.split("\\$");
		salt = parts[2];
		hashword = parts[3];
	}
	
	public String findPass(List<String> dictionary) {
		for (String d : dictionary) {
			String testHash=Sha512Crypt.Sha512_crypt(d,salt,0);
			
			String[]splitHash=testHash.split("\\$");
			
			if (hashword.equals(splitHash[3]))
				return d;
		}
		
		return null;
	}

	public String toString() {
		return username + " - " + salt + " - " + hashword;
	}
}
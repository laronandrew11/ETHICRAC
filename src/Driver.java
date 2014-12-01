import java.io.File;
import java.io.FileNotFoundException;
import java.security.MessageDigest;
import java.util.ArrayList;
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
	MessageDigest SHA512Hash;
	Map<String, String> userPassMap = new HashMap<String, String>(); // map (user, pass)
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Driver driver=new Driver();
		
		try {
			driver.SHA512Hash = MessageDigest.getInstance("SHA-512");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		driver.getRawData();
		driver.loadDictionary(DICTIONARY_FILENAME);
		driver.crackPasswords();
		driver.displayResults();
	}
	
	private void displayResults() {
		int c = 1;
		
		System.out.println("Accounts taken: " + userPassMap.entrySet().size());
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
				if (usernames.contains(parts[0])) {
					if (parts[1].length() > 1)
						accounts.add(new AccountDetails(parts[0],parts[1]));
				}
			}
		}
	}
	
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
	
	public void loadDictionary(String filename)
	{
		dictionary = readLinesFromFile("dict/"+filename);
	}
	
	public void crackPasswords() {
		for (AccountDetails a : accounts) {
			String password = a.findPass(dictionary, SHA512Hash);
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
	
	
	public String findPass(List<String> dictionary, MessageDigest md) {
		for (String d : dictionary) {
			md.update((d).getBytes());
			
			byte[] arr = md.digest();
			StringBuffer sb = new StringBuffer();
			
			for (byte b : arr) {
				sb.append(Integer.toHexString(0xff & b));
			}
			
			System.out.print("(" + arr.length + ", ");
			System.out.println(hashword.length() + ")");
			
			if (hashword.equals(sb.toString()))
				return d;
		}
		
		return null;
	}


	public String toString() {
		return username + " - " + salt + " - " + hashword;
	}
	
}
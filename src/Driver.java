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


public class pwdcrckr {

	
	List<String> usernames=new ArrayList<String>();
	List<String>dictionary;
	//private static final String DICTIONARY_FILENAME="500-worst-passwords.txt";
	List<AccountDetails> accounts = new ArrayList<AccountDetails>();
	Map<String, String> userPassMap = new HashMap<String, String>(); // map (user, pass)
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		pwdcrckr driver=new pwdcrckr();
		
		// ask for file inputs for passwd file, shadow file and dictionary file
		driver.getRawData();
		
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
		Scanner in=new Scanner(System.in);
		
		String passwdPath, shadowPath, dictPath;
		
		System.out.print("Enter input setting: ");
		System.out.println("(0 = defaults, 1 = specify input files)");
		if (in.nextInt() == 0) {
			passwdPath = "files/passwd";
			shadowPath = "files/shadow";
			dictPath = "dict/500-worst-passwords.txt";
		}
		else {
			in.nextLine();
			System.out.print("Enter absolute filepath of passwd file: ");
			passwdPath=in.nextLine();
			System.out.print("Enter absolute filepath of shadow file: ");
			shadowPath=in.nextLine();
			System.out.print("Enter absolute filepath of dictionary file: ");
			dictPath=in.nextLine();
		}
		
		dictionary = readLinesFromFile(dictPath);
		
		List<String> passwdEntries=readLinesFromFile(passwdPath);
		for(String entry:passwdEntries )//each entry in passwd
		{
				String [] parts=entry.split(":");
				if(Integer.parseInt(parts[2])>1000)
					usernames.add(parts[0]);
		}
		
		
		List<String> shadowEntries=readLinesFromFile(shadowPath);//or are we not supposed to see the hashes?
		for(String entry:shadowEntries )
		{
			String [] parts=entry.split(":");
			if (usernames.contains(parts[0]))
				if (parts[1].length() > 1)
					accounts.add(new AccountDetails(parts[0],parts[1]));
		}
		
		Collections.reverse(dictionary);
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
    //static private final String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
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
			if (Sha512Crypt_Optimized.Sha512_crypt(d,salt,0,hashword))
				return d;
		}
		
		return null;
	}

	public String toString() {
		return username + " - " + salt + " - " + hashword;
	}
}
package simonMarketDDoSProtector;

import java.io.File;  
import java.io.FileNotFoundException;  
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.Duration;
import java.io.IOException;

	

public class DDoSProtector {
	Integer timeCriteria;
	Integer occurances;
	HashMap<String, ArrayList<LocalDateTime>> IPCatalog;
	HashSet<String> flaggedIPAddresses;
	
	//Getters and Setters
	private HashMap<String, ArrayList<LocalDateTime>> getIPCatalog() {
		return IPCatalog;
	}
	private void setIPCatalog(HashMap<String, ArrayList<LocalDateTime>> iPCatalog) {
		IPCatalog = iPCatalog;
	}
	private HashSet<String> getFlaggedIPAddresses() {
		return flaggedIPAddresses;
	}
	private void setFlaggedIPAddresses(HashSet<String> flaggedIPAddresses) {
		this.flaggedIPAddresses = flaggedIPAddresses;
	}
	private Integer getTimeCriteria() {
		return timeCriteria;
	}
	private Integer getOccurances() {
		return occurances;
	}

	//Constructor
	DDoSProtector(Integer timeCriteria, Integer occurances){
		this.timeCriteria = timeCriteria;
		this.occurances = occurances;
		this.IPCatalog = new HashMap<String, ArrayList<LocalDateTime>>();
		this.flaggedIPAddresses = new HashSet <String>();
	}
	
	
	//Method for scanning text log input and analyzing traffic
	public void readTextFileInput(File webtraffic) throws FileNotFoundException {
		
	    Scanner myReader = new Scanner(webtraffic);
     
	    while (myReader.hasNextLine()) {
	    	analyzeStringInput(myReader.nextLine());
	      }
	      
	    myReader.close();
	    outputFlaggedIPAddresses(getFlaggedIPAddresses());

	  }
	
	//Checks String Inputs for DDoS attacks
	public void analyzeStringInput(String data) {

        String IPAddress = data.split(" - - ")[0];
        String RemainderLog = data.split(" - - ")[1];
        ArrayList<LocalDateTime> timestampList = new ArrayList<LocalDateTime> ();
        String rawTimestamp = RemainderLog.substring(RemainderLog.indexOf("[")+1,RemainderLog.indexOf(" "));
        LocalDateTime timestamp = LocalDateTime.parse(rawTimestamp, DateTimeFormatter.ofPattern("dd/MMM/uuuu:HH:mm:ss"));
        timestampList.add(timestamp);
        
        if(getIPCatalog().containsKey(IPAddress) ) {
        	
        	getIPCatalog().get(IPAddress).add(timestamp);
        	getIPCatalog().get(IPAddress).removeIf(n ->(Duration.between(n, timestamp).toSeconds()>getTimeCriteria()));
        	
        }
        
        else {
        	getIPCatalog().put(IPAddress, timestampList);
        }
        
        if(getIPCatalog().get(IPAddress).size()>getOccurances()) {
        	getFlaggedIPAddresses().add(IPAddress);
        }
	}
	
	//Method for generating text files with flagged IP Addresses
	public void outputFlaggedIPAddresses(HashSet<String> flaggedIPAddresses) {
		
		DateTimeFormatter formatter =   DateTimeFormatter.ofPattern("MMMdduuuu_HH_mm_ss");
	    String fileSuffix = LocalDateTime.now().format(formatter);
	      
	    File outputFile = new File("Flagged_IPAddresses"+fileSuffix+".txt");
	      
	    try {
	    	BufferedWriter myWriter = new BufferedWriter(new FileWriter(outputFile));
			
			for(String IPAddress : flaggedIPAddresses) {
				myWriter.write(IPAddress);
				myWriter.newLine();
			}
			myWriter.flush();
			myWriter.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	//Method for grabbing config file values 
	public static ArrayList<Integer> grabConfigValues() throws FileNotFoundException {
		ArrayList<Integer > configValues = new ArrayList<Integer>();
		File configFile = new File("config.txt");
		Scanner myReader = new Scanner(configFile);
		
		while(myReader.hasNextLine()) {
			String currentLine = myReader.nextLine();
			configValues.add(Integer.parseInt(currentLine.substring(currentLine.indexOf(":")+1)));
		}
		myReader.close();
		return configValues;
	}
	
	public static void main(String[] args) throws FileNotFoundException {
		
		ArrayList<Integer> configValues = grabConfigValues();
		DDoSProtector test = new DDoSProtector(configValues.get(0),configValues.get(1));
		File webtraffic = new File("apache_log_ddos.txt");
		test.readTextFileInput(webtraffic);
	  }
}

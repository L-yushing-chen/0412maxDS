package VA_standalone;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;

public class MainProgram {

	public static void main(String[] args) {
		
		String content = null;
		
		try {
		    BufferedReader reader = new BufferedReader(new FileReader(args[0]));
		    StringBuilder stringBuilder = new StringBuilder();
		    String line = null;
		    String ls = System.getProperty("line.separator");
		    while ((line = reader.readLine()) != null) {
			    stringBuilder.append(line);
			    stringBuilder.append(ls);
		    }
		    stringBuilder.deleteCharAt(stringBuilder.length() - 1);
		    reader.close();

		    content = stringBuilder.toString();
		    
		} catch (Exception e) {
	           System.err.println("Caught exception " + e.toString());
	    }
		
		//OldInboundMessageServiceImpl OldMSImpl = new OldInboundMessageServiceImpl();
		//OldMSImpl.getInboundMessage(content);
		
		InboundMessageServiceImpl MSImpl = new InboundMessageServiceImpl();
		MSImpl.getInboundMessage(content);
	}

}

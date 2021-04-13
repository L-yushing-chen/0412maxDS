package VA_standalone;

import java.io.InputStream;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;
import java.util.concurrent.ThreadLocalRandom;


import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;


import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * A class that accepts incoming NCPDP message from change healthcare and
 * returns a response.
 *
 */


public class InboundMessageServiceImpl {

	private static final String SENDER_SOFTWARE_END = "</SenderSoftware>";

	private static final String SENDER_SOFTWARE_VERSION_RELEASE_ELEMENT = "<SenderSoftwareVersionRelease>v4.0</SenderSoftwareVersionRelease>";

	private static final String SENDER_SOFTWARE_PRODUCT_ELEMENT = "<SenderSoftwareProduct>Inbound ePrescribing</SenderSoftwareProduct>";

	private static final String SENDER_SOFTWARE_DEVELOPER_ELEMENT = "<SenderSoftwareDeveloper>TECHNATOMY</SenderSoftwareDeveloper>";

	private static final String SENDER_SOFTWARE_START = "<SenderSoftware>";

	private static final String CODE_010 = "<Code>010</Code>";

	private static final String INCOMING_VERIFY_MESSAGE_START = "<Verify>";

	private static final String INCOMING_ERROR_MESSAGE_START = "<Error>";

	private static final String INCOMING_STATUS_MESSAGE_START = "<Status>";

	private static final String SECURE_PROCESSING_CONST_STRING = "http://javax.xml.XMLConstants/feature/secure-processing";

	private static final String EMPTY_STRING = "";

	private static final String UTC_CONST_STRING = "UTC";

	private static final String UTF_8_CONST_STRING = "UTF-8";

	private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

	private static final String EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";

	private static final String EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";

	private static final String DESCRIPTION_MESSAGE_RECEVIED_DESCRIPTION = "<Description>Message Received.</Description>";

	// Renamed the file to address fortify scan issue for unbounded variable in xsd and to to avoid confusion with the original xsd file.
	private static final String VA_EMD_NCPDP_SCRIPT_10_6_XSD = "VA_EMD_NCPDP_SCRIPT_10_6.xsd";
	//private static final String VA_EMD_NCPDP_SCRIPT_10_6_XSD = "C:/sample_input/VA_EMD_NCPDP_SCRIPT_10_6.xsd";

	private static final String ERROR_DESCRIPTION_APPLICATION_ERROR = "<Description>Application Error</Description>";

	private static final String MESSAGE_ERROR_END = "</Error>";

	private static final String ERROR_DESCRIPTION_XSD_VALIDATION = "<Description>XSD Validation Error</Description>";

	private static final String ERROR_CODE_602 = "<Code>602</Code>";

	private static final String MESSAGE_ERROR_START = "<Error>";

	private static final String MESSAGE_BODY_END = "</Body>";

	private static final String MESSAGE_STATUS_END = "</Status>";

	private static final String CODE_000 = "<Code>000</Code>";

	private static final String MESSAGE_STATUS_START = "<Status>";

	private static final String MESSAGE_BODY_START = "<Body>";

	private static final String SENT_TIME_END = "</SentTime>";

	private static final String SENT_TIME_START = "<SentTime>";

	private static final String RELATES_TO_MESSAGE_ID_END_TAG = "</RelatesToMessageID>";

	private static final String RELATES_TO_MESSAGE_ID = "<RelatesToMessageID>";

	private static final String MESSAGE_ID_END = "</MessageID>";

	private static final String MESSAGE_ID_START = "<MessageID>";

	private static final String FROM_ENG_TAG = "</From>";

	private static final String FROM_QUALIFIER_P = "<From Qualifier=\"P\">";

	private static final String FROM_QUALIFIER_D = "<From Qualifier=\"D\">";

	private static final String TO_TAG_END = "</To>";

	private static final String TO_QUALIFIER_D = "<To Qualifier=\"D\">";

	private static final String TO_QUALIFIER_P = "<To Qualifier=\"P\">";

	private static final String MESSAGE_HEADER_END = "</Header>";

	private static final String MESSAGE_HEADER_START = "<Header>";

	private static final String DIGITAL_SIGNATURE_START = "<DigitalSignature Version=\"1.1\">";

	private static final String DIGITAL_SIGNATURE_END = "</DigitalSignature>";

	private static final String DIGEST_METHOD_START = "<DigestMethod>";

	private static final String DIGEST_METHOD_END = "</DigestMethod>";

	private static final String DIGEST_VALUE_START = "<DigestValue>";

	private static final String DIGEST_VALUE_END = "</DigestValue>";

	private static final String SIGNATURE_VALUE_START = "<SignatureValue>";

	private static final String SIGNATURE_VALUE_END = "</SignatureValue>";

	private static final String X509_DATA_START = "<X509Data>";

	private static final String X509_DATA_END = "</X509Data>";

	private static final String MESSAGE_END = "</Message>";


	private static final String MESSAGE_START = "<Message DatatypesVersion=\"20170715\" TransportVersion=\"20170715\" "
			+ "									TransactionDomain=\"SCRIPT\" TransactionVersion=\"20170715\" StructuresVersion=\"20170715\" ECLVersion=\"20170715\">";

	private static final String SENT_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	private static final String INB_MSG_DATE_FORMAT = "MMddyyyy.HH.mm.ss.sss";

	private static final String READY_FOR_AUTOCHECK = "0000";


	private static final String SCRIPT_VERSION = "2017071";

	public String getInboundMessage(String incomingMessage) {

		Date receivedDate = new Date();

		String response = null;

	//	InboundNcpdpMsgEntity inboundeRx;

		String relatesToMessageID = EMPTY_STRING;

		String incomingMessageID = EMPTY_STRING;

		String messageFrom = EMPTY_STRING;

		String messageTo = EMPTY_STRING;

		String newMessageID = null;

		String sentDateString = null;

		StreamSource xsdStreamSource = null;

		Source xsdSource = null;

		InputStream inputStream = null;

		boolean isDigitalSignatureValid = false;

		StringBuffer responseBuffer = new StringBuffer(MESSAGE_START);

		responseBuffer.append(MESSAGE_HEADER_START);

		boolean isNotNewRx = false;

		String incomingMessageOriginal = incomingMessage;

		ValidateDS validateDS = new ValidateDS(incomingMessageOriginal);
		
		

		try {

			
			if(validateDS.getHasDSIndicator() || validateDS.getHasDigitalSignature()) {
				if(!validateDS.getValidation()) {
					// throw new Exception("Digital Signature Invalid");
				}
			}
			
			// put the sent date in response in zulu time format.
			SimpleDateFormat sentDateFormatter = new SimpleDateFormat(SENT_DATE_FORMAT, Locale.US);

			sentDateFormatter.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, UTC_CONST_STRING));

			sentDateString = sentDateFormatter.format(receivedDate);

			// for saving. The server are in central time zone so it should be consistent.
			Date date = new Date();

			// for response.
			SimpleDateFormat inbMsgDateFormatter = new SimpleDateFormat(INB_MSG_DATE_FORMAT, Locale.US);


			String dateString = inbMsgDateFormatter.format(date);



			// 9 digit random number.
			int randomNumber = ThreadLocalRandom.current().nextInt(1, 100000000 + 1);

			newMessageID = new StringBuffer(dateString).append(randomNumber).toString();

			if (incomingMessage.indexOf(MESSAGE_ID_START) != -1) {

				incomingMessageID = incomingMessage.substring(incomingMessage.indexOf(MESSAGE_ID_START) + 11,	incomingMessage.indexOf(MESSAGE_ID_END));

				relatesToMessageID = incomingMessageID;

			}

			if (incomingMessage.indexOf(FROM_QUALIFIER_P) != -1 || incomingMessage.indexOf(FROM_QUALIFIER_D) != -1) {

				if (incomingMessage.indexOf(FROM_QUALIFIER_P) != -1) {

					messageFrom = incomingMessage.substring(incomingMessage.indexOf(FROM_QUALIFIER_P) + 20,	incomingMessage.indexOf(FROM_ENG_TAG));

				} else if (incomingMessage.indexOf(FROM_QUALIFIER_D) != -1) {

					messageFrom = incomingMessage.substring(incomingMessage.indexOf(FROM_QUALIFIER_D) + 20,	incomingMessage.indexOf(FROM_ENG_TAG));
				}

			}

			if (incomingMessage.indexOf(TO_QUALIFIER_D) != -1 || incomingMessage.indexOf(TO_QUALIFIER_P) != -1) {

				if (incomingMessage.indexOf(TO_QUALIFIER_D) != -1) {

					messageTo = incomingMessage.substring(incomingMessage.indexOf(TO_QUALIFIER_D) + 18,	incomingMessage.indexOf(TO_TAG_END));

				} else if (incomingMessage.indexOf(TO_QUALIFIER_P) != -1) {

					messageTo = incomingMessage.substring(incomingMessage.indexOf(TO_QUALIFIER_P) + 18,	incomingMessage.indexOf(TO_TAG_END));
				}

			}

			// now check the message type, if it's not NewRx, then set the response status code to 010 instead of 000.

			if ( (incomingMessage.indexOf(INCOMING_VERIFY_MESSAGE_START) != -1) || (incomingMessage.indexOf(INCOMING_ERROR_MESSAGE_START) != -1 ) ||
					(incomingMessage.indexOf(INCOMING_STATUS_MESSAGE_START) != -1) ) {

				isNotNewRx = true;

			}

			// First do xml validation against xsd using sax parser.

			SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

			// fortify get inputstream and then close it
			inputStream = this.getClass().getClassLoader().getResourceAsStream(VA_EMD_NCPDP_SCRIPT_10_6_XSD);

			xsdStreamSource = new StreamSource(inputStream);
			System.out.println(inputStream != null);
			xsdSource = xsdStreamSource;

			Schema schema = schemaFactory.newSchema(xsdSource);

			SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();

			saxParserFactory.setSchema(schema);

			SAXParser saxparser =  saxParserFactory.newSAXParser();

			XMLReader xmlReader = saxparser.getXMLReader();

            // fortify XXE Fix.
			xmlReader.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
			xmlReader.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
			xmlReader.setFeature(LOAD_EXTERNAL_DTD,false);
			xmlReader.setFeature(SECURE_PROCESSING_CONST_STRING, true);

			// Take a copy of the string to avoid using modified version produced by first XML parser for ValidateDigitalSignature
			/*String incomingMessageOriginal = incomingMessage;*/

			InputSource inputparseXML = new InputSource(new StringReader(incomingMessage));

			inputparseXML.setEncoding(UTF_8_CONST_STRING);

			xmlReader.parse(inputparseXML);

			/* maxhsu move 5 line up 
			if(validateDS.getHasDSIndicator() || validateDS.getHasDigitalSignature()) {
				if(!validateDS.getValidation()) {
					throw new Exception("Digital Signature Invalid");
				}
			}
			*/


			// if validation is successful proceed further.

/*
			inboundeRx = new InboundNcpdpMsgEntity();


			inboundeRx.setMessageId(incomingMessageID);

			// relates to message ID should be null.
			inboundeRx.setRelToMessageId(null);

			inboundeRx.setErxStatusByPatientChkStatus(READY_FOR_AUTOCHECK);

			inboundeRx.setErxStatusByDrugChkStatus(READY_FOR_AUTOCHECK);

			inboundeRx.setErxStatusByProviderChkStatus(READY_FOR_AUTOCHECK);

			inboundeRx.setErxStatusByMessageStatus(READY_FOR_AUTOCHECK);

			inboundeRx.setMessage(incomingMessage);

			inboundeRx.setPharmacyId(0);

			inboundeRx.setCreatedDate(date);

			inboundeRx.setUpdatedDate(date);

			inboundeRx.setReceivedDate(date);

			inboundeRx.setScriptVersion(SCRIPT_VERSION);

			inboundNcpdpMsgService.saveInboundERx(inboundeRx);
*/
			// To and From are flipped.
			responseBuffer.append(TO_QUALIFIER_D);
			responseBuffer.append(messageFrom);
			responseBuffer.append(TO_TAG_END);
			responseBuffer.append(FROM_QUALIFIER_P);
			responseBuffer.append(messageTo);
			responseBuffer.append(FROM_ENG_TAG);
			responseBuffer.append(MESSAGE_ID_START);
			responseBuffer.append(newMessageID);
			responseBuffer.append(MESSAGE_ID_END);
			responseBuffer.append(RELATES_TO_MESSAGE_ID);
			responseBuffer.append(relatesToMessageID);
			responseBuffer.append(RELATES_TO_MESSAGE_ID_END_TAG);
			responseBuffer.append(SENT_TIME_START);
			responseBuffer.append(sentDateString);
			responseBuffer.append(SENT_TIME_END);
			// sender software start 201707
			responseBuffer.append(SENDER_SOFTWARE_START);
			responseBuffer.append(SENDER_SOFTWARE_DEVELOPER_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_PRODUCT_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_VERSION_RELEASE_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_END);
			// sender software end.
			responseBuffer.append(DIGITAL_SIGNATURE_START);
			responseBuffer.append(DIGEST_METHOD_START);
			responseBuffer.append(validateDS.getDigestMethod());
			responseBuffer.append(DIGEST_METHOD_END);
			responseBuffer.append(DIGEST_VALUE_START);
			responseBuffer.append(validateDS.getCreatedeRxDigest());
			responseBuffer.append(DIGEST_VALUE_END);
			responseBuffer.append(SIGNATURE_VALUE_START);
			responseBuffer.append(validateDS.getCreatedDigitalSignature());
			responseBuffer.append(SIGNATURE_VALUE_END);
			responseBuffer.append(X509_DATA_START);
			responseBuffer.append(validateDS.getTestingPubKey());
			responseBuffer.append(X509_DATA_END);
			responseBuffer.append(DIGITAL_SIGNATURE_END);
			responseBuffer.append(validateDS.getCheckpoint());
			responseBuffer.append(validateDS.getElementsToSignWith());
			responseBuffer.append(MESSAGE_HEADER_END);
			responseBuffer.append(MESSAGE_BODY_START);
			responseBuffer.append(MESSAGE_STATUS_START);

			if(isNotNewRx == true){
				responseBuffer.append(CODE_010);
			}
			else{
				responseBuffer.append(CODE_000);
			}

			responseBuffer.append(DESCRIPTION_MESSAGE_RECEVIED_DESCRIPTION);
			responseBuffer.append(MESSAGE_STATUS_END);
			responseBuffer.append(MESSAGE_BODY_END);
			responseBuffer.append(MESSAGE_END);

			response = responseBuffer.toString();

		} catch (SAXException ex) {

	
			// build error response. To and From are flipped.

			responseBuffer.append(TO_QUALIFIER_D);
			responseBuffer.append(messageFrom);
			responseBuffer.append(TO_TAG_END);
			responseBuffer.append(FROM_QUALIFIER_P);
			responseBuffer.append(messageTo);
			responseBuffer.append(FROM_ENG_TAG);
			responseBuffer.append(MESSAGE_ID_START);
			responseBuffer.append(newMessageID);
			responseBuffer.append(MESSAGE_ID_END);
			responseBuffer.append(RELATES_TO_MESSAGE_ID);
			responseBuffer.append(relatesToMessageID);
			responseBuffer.append(RELATES_TO_MESSAGE_ID_END_TAG);
			responseBuffer.append(SENT_TIME_START);
			responseBuffer.append(sentDateString);
			responseBuffer.append(SENT_TIME_END);
			// sender software start 201707
			responseBuffer.append(SENDER_SOFTWARE_START);
			responseBuffer.append(SENDER_SOFTWARE_DEVELOPER_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_PRODUCT_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_VERSION_RELEASE_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_END);
			// sender software end.

			// Append DS for testing
			responseBuffer.append(validateDS.getCheckpoint());
			responseBuffer.append(validateDS.getTestingPubKey());
			responseBuffer.append(validateDS.getDigestMethod());
			responseBuffer.append(validateDS.getCreatedDigitalSignature());
			responseBuffer.append(validateDS.getElementsToSignWith());
			responseBuffer.append(MESSAGE_HEADER_END);

			responseBuffer.append(MESSAGE_BODY_START);
			responseBuffer.append(MESSAGE_ERROR_START);
			responseBuffer.append(ERROR_CODE_602);
			responseBuffer.append(ERROR_DESCRIPTION_XSD_VALIDATION);
			responseBuffer.append(MESSAGE_ERROR_END);
			responseBuffer.append(MESSAGE_BODY_END);
			responseBuffer.append(MESSAGE_END);

			response = responseBuffer.toString();

		} catch (Exception e) {

			System.out.println("Error in InboundNCPDPMessageServiceImpl:" + e.getMessage());

			// build error response. To and From are flipped.

			responseBuffer.append(TO_QUALIFIER_D);
			responseBuffer.append(messageFrom);
			responseBuffer.append(TO_TAG_END);
			responseBuffer.append(FROM_QUALIFIER_P);
			responseBuffer.append(messageTo);
			responseBuffer.append(FROM_ENG_TAG);
			responseBuffer.append(MESSAGE_ID_START);
			responseBuffer.append(newMessageID);
			responseBuffer.append(MESSAGE_ID_END);
			responseBuffer.append(RELATES_TO_MESSAGE_ID);
			responseBuffer.append(relatesToMessageID);
			responseBuffer.append(RELATES_TO_MESSAGE_ID_END_TAG);
			responseBuffer.append(SENT_TIME_START);
			responseBuffer.append(sentDateString);
			responseBuffer.append(SENT_TIME_END);
			// sender software start 201707
			responseBuffer.append(SENDER_SOFTWARE_START);
			responseBuffer.append(SENDER_SOFTWARE_DEVELOPER_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_PRODUCT_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_VERSION_RELEASE_ELEMENT);
			responseBuffer.append(SENDER_SOFTWARE_END);
			// sender software end.
			responseBuffer.append("Invalid Digital Signature");
			responseBuffer.append(validateDS.getCheckpoint());
			responseBuffer.append(validateDS.getTestingPubKey());
			responseBuffer.append(validateDS.getDigestMethod());
			responseBuffer.append(validateDS.getCreatedDigitalSignature());
			responseBuffer.append(validateDS.getElementsToSignWith());
			responseBuffer.append(MESSAGE_HEADER_END);
			responseBuffer.append(MESSAGE_BODY_START);
			responseBuffer.append(MESSAGE_ERROR_START);
			responseBuffer.append(ERROR_CODE_602);
			responseBuffer.append(ERROR_DESCRIPTION_APPLICATION_ERROR);
			responseBuffer.append(MESSAGE_ERROR_END);
			responseBuffer.append(MESSAGE_BODY_END);
			responseBuffer.append(MESSAGE_END);

			response = responseBuffer.toString();

		} finally {

			// StreamUtilities.safeClose(inputStream);

	//		inboundeRx = null;
			relatesToMessageID = null;
			messageFrom = null;
			messageTo = null;
			incomingMessageID = null;

			xsdSource = null;
			xsdStreamSource = null;
			responseBuffer = null;
		}
        System.out.println("response[" + response + "]");
		return response;
	}

}

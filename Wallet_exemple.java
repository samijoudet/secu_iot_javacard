package bank.purse;

import javacard.framework.*;
import javacardx.framework.*;

public class Wallet extends Applet {
  /* constants declaration */
  // code of CLA byte in the command APDU header
  final static byte Wallet_CLA =(byte)0xB0;

	// CLA identifies the command structure.

  // codes of INS byte in the command APDU header
  final static byte VERIFY = (byte) 0x20;
  final static byte CREDIT = (byte) 0x30;
  final static byte DEBIT = (byte) 0x40;
  final static byte GET_BALANCE = (byte) 0x50;

	// INS specifies the application instructions.

  // maximum balance
  
  final static short MAX_BALANCE = 0x7FFF;
  
  // maximum transaction amount
  
  final static byte MAX_TRANSACTION_AMOUNT = 127;

	// Maximum balance and transaction amount.

  // maximum number of incorrect tries before the
  // PIN is blocked
  final static byte PIN_TRY_LIMIT =(byte)0xfe;
  
  // maximum size PIN
  final static byte MAX_PIN_SIZE =(byte)0x08;

	// PIN object parameters.

  // signal that the PIN verification failed
  final static short SW_VERIFICATION_FAILED = 0x6300;
   
  // signal the PIN validation is required
  // for a credit or a debit transaction
  final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
   
  // signal invalid transaction amount
  // amount > MAX_TRANSACTION_MAOUNT or amount < 0
  final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
   
  // signal that the balance exceed the maximum
  final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
   
  // signal the balance becomes negative
  final static short SW_NEGATIVE_BALANCE = 0x6A85;

	// Applet-specific static words.

  /* instance variables declaration */
  OwnerPIN pin;
  short balance;

	 

  private Wallet (byte[] bArray, short bOffset, byte bLength){
   
    // It is good programming practice to allocate
    // all the memory that an applet needs during
    // its lifetime inside the constructor
    pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
   
    // The installation parameters contain the PIN
    // initialization
    value pin.update(bArray, bOffset, bLength);
    register();
  } // end of the constructor
  
   

	// Private constructor -- an instance of class Wallet is instantiated by its install method.
    // The applet registers itself with the JCRE by calling the register method, which is defined in class Applet.

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    // create a Wallet applet instance
    new Wallet(bArray, bOffset, bLength);
  } // end of install method

	//Method install is invoked by the JCRE to create an applet instance and to register the instance with the JCRE. The installation parameters are supplied in the byte array parameter, and must be in a format defined by the applet. They are used to initialize the applet instance.

  public boolean select() {
    // The applet declines to be selected
    // if the pin is blocked.
    if ( pin.getTriesRemaining() == 0 ) return false;
    return true;
  }// end of select method

	// This method is called by the JCRE to indicate that this applet has been selected. It performs necessary initialization, which is required to process the subsequent APDU messages.

  public void deselect() {
    // reset the pin value
    pin.reset();
  }

	// This method is called by the JCRE to inform the applet that it should perform any clean-up and bookkeeping tasks before the applet is deselected.

  public void process(APDU apdu) {
    // APDU object carries a byte array (buffer) to
    // transfer incoming and outgoing APDU header
    // and data bytes between card and CAD
    // At this point, only the first header bytes
    // [CLA, INS, P1, P2, P3] are available in
    // the APDU buffer.
    // The interface javacard.framework.ISO7816
    // declares constants to denote the offset of
    // these bytes in the APDU buffer
    byte[] buffer = apdu.getBuffer();

	// After the applet is successfully selected, the JCRE dispatches incoming APDUs to the process 
    // method.The APDU object is owned and maintained by the JCRE. It encapsulates details of the 
    // underlying transmission protocol (T0 or T1 as specified in ISO 7816-3) by providing a common 
    // interface.

    // check SELECT APDU command
    if ((buffer[ISO7816.OFFSET_CLA] == 0) &&
        (buffer[ISO7816.OFFSET_INS] == (byte)(0xA4))) return;

	// The JCRE also passes the SELECT APDU command to the applet.

    // verify the reset of commands have the
    // correct CLA byte, which specifies the
    // command structure
    if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA)
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

	// When an error occurs, the applet may decide to terminate the process, and to throw an exception containing the status word (SW1, SW2) to indicate the processing state of the card. An exception that is not caught by an applet is caught by the JCRE.

    switch (buffer[ISO7816.OFFSET_INS]) {
      case GET_BALANCE: getBalance(apdu);
        return;
      case DEBIT: debit(apdu);
        return;
      case CREDIT: credit(apdu);
        return;
      case VERIFY: verify(apdu);
        return;
      default: ISOException.throwIt (ISO7816.SW_INS_NOT_SUPPORTED);
    }
  } // end of process method

	// The main function of the process method is to perform the action specified in the APDU, and to return an appropriate response to the terminal. The INS byte specifies the type of action to be performed.

  private void credit(APDU apdu) {
    // access authentication
    if ( ! pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    byte[] buffer = apdu.getBuffer();
    // Lc byte denotes the number of bytes in the
    // data field of the command APDU
    byte numBytes = buffer[ISO7816.OFFSET_LC];
   
    // indicate that this APDU has incoming data
    // and receive data starting at the offset
    // ISO7816.OFFSET_CDATA following the 5 header
    // bytes.
    byte byteRead = (byte)(apdu.setIncomingAndReceive());
   
    // it is an error if the number of data bytes
    // read does not match the number in Lc byte
    if (byteRead != 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
   
    // get the credit amount
    byte creditAmount = buffer[ISO7816.OFFSET_CDATA];
   
    // check the credit amount
    if ( ( creditAmount > MAX_TRANSACTION_AMOUNT) || ( creditAmount < 0 ) )
      ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
   
    // check the new balance
    if ( ( balance + creditAmount) > MAX_BALANCE ) ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
   
    // credit the amount
    balance = (short)(balance + creditAmount);
  
  } // end of deposit method

	// The parameter APDU object contains a data field, which specifies the amount to be added to the balance. Upon receiving the APDU object from the JCRE, the first 5 bytes (CLA, INS, P1, P2, Lc) are available in the APDU buffer. Their offsets in the APDU buffer are specified in the interface ISO7816. Because the data field is optional, the applet needs to explicitly inform the JCRE that it needs to retrieve additional data bytes. The card and the CAD communicate by exchanging APDU commands (the command APDU and response APDU). In the deposit case, the response APDU contains no data field. The JCRE returns the response APDU with status word 0x9000 (normal processing). Applet developers need not be concerned with the details of constructing the proper response APDU. When the JCRE catches an exception (which indicates an error during processing the command) the JCRE constructs the response APDU using the status word contained in the exception.

  private void debit(APDU apdu) {
   
    // access authentication
    if ( ! pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
   
    byte[] buffer = apdu.getBuffer();
    byte numBytes = (byte)(buffer[ISO7816.OFFSET_LC]);
    byte byteRead = (byte)(apdu.setIncomingAndReceive());
   
    if (byteRead != 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
   
    // get debit amount
    byte debitAmount = buffer[ISO7816.OFFSET_CDATA];
   
    // check debit amount
    if ( ( debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0 ) )
      ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
   
    // check the new balance
    if ( ( balance-- debitAmount) < 0 ) ISOException.throwIt(SW_NEGATIVE_BALANCE);
   
    balance = (short) (balance -- debitAmount);
  } // end of debit method

	//  In the debit method, the APDU object contains a data field that specifies the amount to be debited from the balance.

  private void getBalance(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    // inform system that the applet has finished
    // processing the command and the system should
    // now prepare to construct a response APDU
    // which contains data field
    short le = apdu.setOutgoing();
   
    if ( le < 2 ) ISOException.throwItISO7816.SW_WRONG_LENGTH);
   
    //informs the CAD the actual number of bytes
    //returned
    apdu.setOutgoingLength((byte)2);
   
    // move the balance data into the APDU buffer
    // starting at the offset 0
    buffer[0] = (byte)(balance >> 8);
    buffer[1] = (byte)(balance & 0xFF);
   
    // send the 2-balance byte at the offset
    // 0 in the apdu buffer
    apdu.sendBytes((short)0, (short)2);
   
  
  } // end of getBalance method

	// The method getBalance returns the Wallet's balance in the data field of the response APDU. Because the data field in the response APDU is optional, the applet must explicitly inform the JCRE of the additional data. The JCRE uses the data array in the APDU object buffer and the proper status word to construct a complete response APDU.

  private void verify(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    // retrieve the PIN data for validation.
    byte byteRead = (byte)(apdu.setIncomingAndReceive());
   
    // check pin
    // the PIN data is read into the APDU buffer
    // at the offset ISO7816.OFFSET_CDATA
    // the PIN data length = byteRead
    if ( pin.check(buffer, ISO7816.OFFSET_CDATA,byteRead) == false )
      ISOException.throwIt(SW_VERIFICATION_FAILED);
  } // end of validate method
} // end of class Wallet



// minimalistic TEE
// What is a TEE?
// A TEE is a Trusted Execution Environment. It is a secure area of a main processor. 
// It guarantees code and data loaded inside to be protected with respect to confidentiality 
// and integrity.
// A TEE consists of two components:
// - A secure operating system (TEE OS) running in the secure area
// - A client application running outside the secure area
// The TEE OS provides a set of services to the client application.
// The card will be able to sign a data transmitted by the terminal-side application on demand, thus playing the role of a minimalistic TEE
// sign a data mean that the card will compute a hash of the data and then encrypt it with the private key of the card
// the terminal-side application will be able to verify the signature by decrypting the hash with the public key of the 
// card and then compare it with the hash of the data.

// en français : on envois une donnée à la carte, la carte la signe et la renvois au terminal qui vérifie la signature.
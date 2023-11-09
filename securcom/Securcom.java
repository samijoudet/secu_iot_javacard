package securcom;

import javacard.framework.*;

public class Securcom extends Applet {
    // AID for our applet
    // final static byte[] AID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01, 0x01};

    // CLA byte for our applet
    final static byte SECURCOM_CLA = (byte) 0xB0;

    // INS byte for verifying the PIN
    final static byte VERIFY_PIN_INS = (byte) 0x20;

    // INS byte for changing the PIN
    final static byte CHANGE_PIN_INS = (byte) 0x30;

    // PIN try limit and max size PIN
    final static byte PIN_TRY_LIMIT = (byte) 0xf0;
    final static byte MAX_PIN_SIZE = (byte) 0x04;

    // PIN object
    private OwnerPIN pin;

    // PIN value
    private final static byte[] PIN_VALUE = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};

    // Constructor
    public Securcom(byte[] bArray, short bOffset, byte bLength) {
        // Create a new PIN object
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        // Set the PIN value

        // pin.update(bArray, bOffset, bLength); // PIN value is set on the fly during the installation
        pin.update(PIN_VALUE, (short) 0, (byte) PIN_VALUE.length); // PIN value is set in the code
        register();
    }

    // Install method
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Create a new instance of our applet
        new Securcom(bArray, bOffset, bLength);
    }

    // Select method
    public boolean select() {
        // The applet declines to be selected if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }
        return true;
    }

    // Deselect method
    public void deselect() {
        // Reset the pin value
        pin.reset();
    }

    // Process method
    public void process(APDU apdu) throws ISOException {
        // Get the APDU buffer
        byte[] buffer = apdu.getBuffer();

        // Check the CLA byte
        if (buffer[ISO7816.OFFSET_CLA] != SECURCOM_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Get the INS byte
        byte ins = buffer[ISO7816.OFFSET_INS];

        // Handle the INS byte
        switch (ins) {
            case VERIFY_PIN_INS:
                verifyPIN(apdu);
                break;
            case CHANGE_PIN_INS:
                changePIN(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // Verify PIN method
    private void verifyPIN(APDU apdu) {
        // Get the APDU buffer
        byte[] buffer = apdu.getBuffer();

        // Get the PIN value from the APDU
        byte[] pinValue = new byte[4];
        short pinLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); 

        // Get the PIN value from the APDU
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short dataOffset = ISO7816.OFFSET_CDATA;
        byte[] data = buffer;
        short pinOffset = (short) 0;
        while (dataLength > 0) {
            pinValue[pinOffset++] = data[dataOffset++];
            dataLength--;
        }

        // Compare the PIN values
        if (pin.check(pinValue, (short) 0, (byte) pinLength) == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    // Change PIN method
    private void changePIN(APDU apdu) {
        // Get the APDU buffer
        byte[] buffer = apdu.getBuffer();

        // Get the PIN value from the APDU
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short dataOffset = ISO7816.OFFSET_CDATA;
        byte[] data = buffer;
        byte[] newPINValue = new byte[4];
        short newPINOffset = (short) 0;
        while (dataLength > 0) {
            newPINValue[newPINOffset++] = data[dataOffset++];
            dataLength--;
        }

        // Set the new PIN value
        pin.update(newPINValue, (short) 0, (byte) newPINValue.length);
    }
}

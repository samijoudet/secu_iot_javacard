package helloworld;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.framework.OwnerPIN;
import javacard.security.*;


public class RSA extends Applet {

    private final static byte[] realPIN = { 0x00, 0x00, 0x00, 0x00 };

    private static OwnerPIN pin;

    private static KeyPair keypair;

    private static RSAPublicKey pk;

    private static RSAPrivateKey sk;

    private boolean pinVerified = false;

    public static void install(byte[] buffer, short offset, byte length)

    {
        // GP-compliant JavaCard applet registration
        pin = new OwnerPIN((byte) 5, (byte) 5);
        pin.update(realPIN, (byte) 0, (byte) 4);
        new RSA().register();

        keypair = new KeyPair(KeyPair.ALG_RSA, (short) 512);
        keypair.genKeyPair();
        pk = (RSAPublicKey) keypair.getPublic();
        sk = (RSAPrivateKey) keypair.getPrivate();
    }

    public void process(APDU apdu) {
        // Good practice: Return 9000 on SELECT
        if (selectingApplet()) {
            return;
        }
        
        byte[] buffer = apdu.getBuffer();

        switch (buffer[ISO7816.OFFSET_INS]) {
            case (byte) 0x22: // Case for PIN code
                byte[] buf = apdu.getBuffer();
                byte size = (byte) (apdu.setIncomingAndReceive());
                if (pin.check(buf, ISO7816.OFFSET_CDATA, (byte) (size))) {
                    pinVerified = true;
                    return;
                } else
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

                break;
            case (byte) 0x23: // Sign message 
                if (pinVerified) {
                    sendN(apdu);
                    return;
                } else
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                break;
            case (byte) 0x24: // Retrieve exponent for public key pk
                if (pinVerified) {
                    short len = pk.getExponent(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                    return;
                } else
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                break;
            case (byte) 0x25: // Retrieve modulus for public key pk
                if (pinVerified) {
                    short len = pk.getModulus(apdu.getBuffer(), ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                    return;
                } else
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                break;
            default:
                // good practice: If you don't know the Instruction, say so:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    public void sendN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short incomming = apdu.setIncomingAndReceive();
        Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        sig.init(sk, Signature.MODE_SIGN);
        short signatureLength = sig.sign(
                buf, (short) ISO7816.OFFSET_CDATA,
                incomming, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, signatureLength);
    }
}

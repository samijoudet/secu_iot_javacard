from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.CardConnectionObserver import CardConnectionObserver
import sys


# Vous pouvez maintenant envoyer des commandes APDU à la carte Java
# Décomposition d'une commande APDU (C-APDU)
# CLA (Class) : Le premier octet est la classe de l'instruction.
cla = 0xB0
# INS (Instruction) : Le deuxième octet est le code d'instruction qui spécifie l'opération à effectuer.
ins = 0x20  # Exemple : VERIFY PIN
# P1 et P2 (Parameter 1 et 2 additionnel pour l'instruction.)
p1 = 0x00  # Exemple : Paramètre 1 00
p2 = 0x00  # Exemple : Paramètre 2 00
lc = 0x00  # Exemple : Longueur de données = initialement 0 octets

# Data : Les octets suivants (dans ce cas, 4 octets) contiennent les données de commande.
data = bytes.fromhex('01020304')  # Exemple de données
# Lc (Length of Command Data)
lc = len(data)  # Longueur de données = 4 octets

# Maintenant, nous pouvons assembler ces parties pour créer la commande APDU complète.
# La commande APDU se compose de CLA, INS, P1, P2, Lc, et les données.
apdu_command = bytes([cla, ins, p1, p2, lc]) + data

class TracerAndSELECTInterpreter(CardConnectionObserver):
    """This observer will interprer SELECT and GET RESPONSE bytes
    and replace them with a human readable string."""

    def update(self, cardconnection, ccevent):

        if 'connect' == ccevent.type:
            print('connecting to ' + cardconnection.getReader())

        elif 'disconnect' == ccevent.type:
            print('disconnecting from ' + cardconnection.getReader())

        elif 'command' == ccevent.type:
            str = toHexString(ccevent.args[0])
            str = str.replace("A0 A4 00 00 02", "SELECT")
            str = str.replace("A0 C0 00 00", "GET RESPONSE")
            print('>', str)

        elif 'response' == ccevent.type:
            if [] == ccevent.args[0]:
                print('<  []', "%-2X %-2X" % tuple(ccevent.args[-2:]))
            else:
                print('<',
                      toHexString(ccevent.args[0]),
                      "%-2X %-2X" % tuple(ccevent.args[-2:]))


for reader in readers():
    try:
        
        # we request any type and wait for 10s for card insertion
        cardtype = AnyCardType()
        cardrequest = CardRequest(timeout=10, cardType=cardtype)
        cardservice = cardrequest.waitforcard()

        # create an instance of our observer and attach to the connection
        observer = TracerAndSELECTInterpreter()
        cardservice.connection.addObserver(observer)

        # connect and send APDUs
        # the observer will trace on the console
        cardservice.connection.connect()

        apdu = apdu_command
        response, sw1, sw2 = cardservice.connection.transmit(apdu)

    except NoCardException:
        print(reader, 'no card inserted')
    finally:
        print('------------------')

if 'win32' == sys.platform:
    print('press Enter to continue')
    sys.stdin.read(1)


print(f"Response: {response.hex()}")

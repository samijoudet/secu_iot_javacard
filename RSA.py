import os
import sys
import time
from collections import deque
import logging
import subprocess
import platform
from smartcard.System import readers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import binascii
log = logging.getLogger()
log.setLevel(logging.DEBUG)
term_size = 5
time_limit = 1
queue = deque([], term_size)
shell = None
delete_applet_script = \
"mode_201,"\
"gemXpressoPro,"\
"enable_trace,"\
"enable_timer,"\
"establish_context,"\
"card_connect,"\
"select -AID A000000018434D00,"\
"open_sc -security 0 -keyind 0 -keyver 0 -key 47454d5850524553534f53414d504c45,"\
"delete -AID a00000006203010c060102,"\
"delete -AID 0a0000006203010c0601,"\
"card_disconnect,"\
"release_context"

upload_applet_script = \
"mode_201,"\
"enable_trace,"\
"enable_timer,"\
"establish_context,"\
"card_connect,"\
"select -AID A000000018434D00,"\
"open_sc -security 3 -keyind 0 -keyver 0 -key 47454d5850524553534f53414d504c45 -keyDerivation visa2,"\
"install -file ./helloworld/javacard/helloworld.cap -sdAID A000000018434D00 -nvCodeLimit 4000,"\
"card_disconnect,"\
"release_context"\

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def print_info(queue, cmd):
    time.sleep(0.3)
    for _ in range(len(queue)):
        sys.stdout.write("\x1b[1A\x1b[2K")
    queue.append(cmd)
    for i in range(len(queue)):
        sys.stdout.write(bcolors.OKBLUE + queue[i] + "\n" + bcolors.ENDC)


def exec_shell(shell, cmd, _print=False):
    cmd = cmd.encode("utf-8")
    shell.stdin.write(cmd + b'\n')
    if _print:
        print(cmd)
    return shell


def encodeN(N):
    N = ''.join([format(ord(char), 'x') for char in N])
    N = N.zfill(len(N) + 1) if len(N) % 2 == 1 else N
    size = int(len(N) / 2)
    N = ' '.join([N[i] + N[i + 1] for i in range(0, len(N) - 1, 2)])
    return N, str(size).zfill(2)

# Rechercher les lecteurs de cartes
r = readers()
if not r:
    print("Aucun lecteur de carte trouvé.")
    exit()

print("\n\n")
print("=" * 30)
print("Welcome ")
print("[WARNING] You need gpshell and scriptor.")
time.sleep(4)
print("=" * 30)

shell = subprocess.Popen(["gpshell"],
                         #stdout=sys.stdout,
                         stdin=subprocess.PIPE,
                         #stderr=sys.stderr
                         )

logging.info("Start talking with the card ...\n")
logging.info("Deleting previous applet and uploading the new one.")
for cmd in delete_applet_script.split(","):
    shell = exec_shell(shell, cmd)

for cmd in upload_applet_script.split(","):
    shell = exec_shell(shell, cmd)

print("\n")
logging.info("Done.")

print("\n")
print("Captured output. Check if there is no errors: ")
print(bcolors.OKBLUE)
print(shell.communicate())
print(bcolors.ENDC)

shell = subprocess.Popen(["scriptor"],
                         stdout=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)

time.sleep(1)
# initialisation
cmd = "00 A4 04 00 08 A0 00 00 00 62 03 01 0C 06 01 02"
shell = exec_shell(shell, cmd, _print=True)

# pin
pin = input("Enter pin :")
pin = ' '.join([x.zfill(2) for x in pin.strip()])
cmd = f"00 22 00 00 04 {pin}"
shell = exec_shell(shell, cmd, _print=True)

# send N
N, size = encodeN(input("Enter a N to sign :"))
cmd = f"00 23 00 00 {size} {N} 40"
shell = exec_shell(shell, cmd, _print=True)

# retrieve N
cmd = f"00 C0 00 00 40"
shell = exec_shell(shell, cmd)

# retrieve e
cmd = f"00 24 00 00 03"
shell = exec_shell(shell, cmd)

# retrieve pk
cmd = f"00 25 00 00 40"
shell = exec_shell(shell, cmd)

# show response at the end (no choice)
response = shell.communicate()[0].decode("utf-8")
print(response)
print(bcolors.OKBLUE)
print(response)
print(bcolors.ENDC)

response = response.split("\n")

exponant_string = response[14]
signedN_string = response[8:12]
pk_string = response[16:20]

exponant_string = exponant_string.split(":")[0][2:]
signedN_string = ''.join(signedN_string).split(":")[0][2:]
pk_string  = ''.join(pk_string).split(":")[0][2:]

print("="*30)
print("e = " + exponant_string)
print("signed N = " + signedN_string)
print("public key= " + pk_string)

# Function to convert hex string to an integer
def hex_to_int(hex_str):
    return int(hex_str.replace(" ", ""), 16)
# Convert hex strings to integers
e = 65537
byte_data = bytes.fromhex(N)
n = hex_to_int(pk_string)
signature = binascii.unhexlify(signedN_string.replace(" ", ""))

# Original message that was signed (update this with the actual message)
original_message = b"Your original message"

# Create a public key object
public_key = rsa.RSAPublicNumbers(e, n).public_key()

# Verify the signature
try:
    public_key.verify(
        signature,
        byte_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("Signature is valid.")
except Exception as e:
    print("Signature is valid !", e)

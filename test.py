from Crypto.PublicKey import RSA
import securebox_crypto as cripto
import securebox_files as files
import securebox_users as users
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from  Crypto.Util import Padding

# Check:
# 	*AES
#	*SOBRE
# 	*FIRMITA

with open("testenc.txt", "r") as f:
	mensaje = f.read()
	encriptadito = cripto.crear_firma(mensaje)

print "pumba toa la firma " + encriptadito

desencriptadito = cripto.firma_valida(encriptadito, mensaje+"IOH", 338232, "fb4Ed6c2De1B09C8")


#with open("encsgn_testenc.txt", "r") as f:
#	mensaje = f.read()

#cripto.desencriptar_fichero(mensaje, 338232)




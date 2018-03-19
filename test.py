from Crypto.PublicKey import RSA
import securebox_crypto as cripto
import securebox_files as files
import securebox_users as users
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from  Crypto.Util import Padding


with open("testenc.txt", "r") as f:
	clave = get_random_bytes(32)
	print "LA CLAVE D LA VIDA: " + clave
	encriptadito = cripto.crear_sobre(clave, 338232, "fb4Ed6c2De1B09C8")

print "pumba tol sobre " + encriptadito

desencriptadito = cripto.abrir_sobre(encriptadito)

print "pumba aqui te pillo aqui te desencripto: " + desencriptadito

#with open("encsgn_testenc.txt", "r") as f:
#	mensaje = f.read()

#cripto.desencriptar_fichero(mensaje, 338232)




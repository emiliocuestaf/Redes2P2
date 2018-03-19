from Crypto.PublicKey import RSA
import securebox_crypto as cripto

with open("encsgn_testenc.txt", "r") as f:
	mensaje = f.read()

cripto.desencriptar_fichero(mensaje, 338232)



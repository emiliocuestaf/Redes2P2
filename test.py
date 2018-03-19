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


mensaje_encriptado = cripto.firmar_y_encriptar("testenc.txt", ID_receptor=338232, token="fb4Ed6c2De1B09C8")

mensaje=cripto.desencriptar_all(open("encsgn_testenc.txt","r").read(), ID_emisor="338232", token="fb4Ed6c2De1B09C8")

print mensaje
#with open("encsgn_testenc.txt", "r") as f:
#	mensaje = f.read()

#cripto.desencriptar_fichero(mensaje, 338232)




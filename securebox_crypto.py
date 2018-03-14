import python *
import pycryptodome *
import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

IVLEN = 16
AESCLEN = 32

# utiliza HASH y crea la firma 

def crear_firma(mensaje):
	# Creamos el hash
	h = SHA256.new()
	# Lo aplicamos en el mensaje
	h.update(mensaje)	

	clave_privada = RSA.import_key(open("noEsLaClave.dat", "r").read())
	cifrador = PKCS1_OAEP.new(clave_privada)
	return cifrador.encrypt(h.digest())

# cifra el mensaje+firma de manera simetrica usando AES

def encriptar_AES(mensaje, clave):

	iv = get_random_bytes(IVLEN)

	cifrado_aes = AES.new(clave, AES.MODE_CBC, iv)
	return cipher_aes.encrypt(mensaje)


# coge la clave del AES del anadir firma y la cifra con RSA con la clave publica del receptor

def crear_sobre(clave, ID_usuario)
	
	# Creamos la solicitud de la clave publica al servidor 

	url = 'https://vega.ii.uam.es:8080/api/users/getPublicKey'
	args = {'userID': ID_usuario}
	r = requests.post(url, json=args)
	
	# r.text contiene la respuesta del servidor (la clave publica)

	clave_publica = RSA.import_key(r.text)

	# Encriptamos la clave del AES

	cifrador = PKCS1_OAEP.new(clave_publica)
	return cifrador.encrypt(clave)



# Encrypt the session key with the public RSA key

# RSA con clave privada del sender
#def encriptar_firma(mensaje, ID_sender)

# RSA con clave publica del sender
def desencriptar_firma(firma, ID_sender)





# descifra AES
def desencriptar_AES(AES_key)

def comprobar_hash(firma, hash)

# descifra la clave del AES con la clave privada del receptor
def abrir_sobre(c_Key)



# Se encarga de todo el proceso de cifrar un mensaje

def encriptar_all(mensaje, ID_usuario):

	# Firmamos el mensaje

	firma = crear_firma(mensaje)

	# Generamos la clave que usara AES y encriptamos con dicha clave

	clave = get_random_bytes(AESCLEN)
	c_mensaje = encriptar_AES(firma + mensaje, clave)

	# Ciframos la clave para crear el sobre

	sobre = crear_sobre(clave, ID_usuario)

	return sobre + c_mensaje

	

def desencriptar_all()


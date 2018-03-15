import python *
import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

IVLEN = 16
AESCLEN = 32

# Funciones para encriptar

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
	return iv + cipher_aes.encrypt(mensaje)


# coge la clave del AES del anadir firma y la cifra con RSA con la clave publica del receptor

def crear_sobre(clave, ID_receptor):
	
	# Creamos la solicitud de la clave publica al servidor 

	url = 'https://vega.ii.uam.es:8080/api/users/getPublicKey'
	args = {'userID': ID_receptor}
	r = requests.post(url, json=args)
	
	# r.text contiene la respuesta del servidor (la clave publica)

	clave_publica = RSA.import_key(r.text)

	# Encriptamos la clave del AES

	cifrador = PKCS1_OAEP.new(clave_publica)
	return cifrador.encrypt(clave)


# Se encarga de todo el proceso de cifrar un mensaje

def encriptar_all(mensaje, ID_receptor):

	# Firmamos el mensaje

	firma = crear_firma(mensaje)

	# Generamos la clave que usara AES y encriptamos con dicha clave

	clave = get_random_bytes(AESCLEN)
	c_mensaje = encriptar_AES(firma + mensaje, clave)

	# Ciframos la clave para crear el sobre

	sobre = crear_sobre(clave, ID_receptor)

	return sobre + c_mensaje


# Funciones para desencriptar

# descifra la clave del AES con la clave privada del receptor
def abrir_sobre(c_clave):

	# Conseguimos la clave privada del usuario

	clave_privada = RSA.import_key(open("noEsLaClave.dat", "r").read())

	cifrador = PKCS1_OAEP.new(clave_privada)

	return cifrador.decrypt(c_clave)


# descifra AES
def desencriptar_AES(clave, iv, c_mensaje):

	cifrador = AES.new(clave, AES.MODE_CBC, iv)

	return cifrador.decrypt(c_mensaje)

# Devuelve el hash, gracias a RSA con la clave publica del emisor

def desencriptar_firma(firma, ID_emisor):

	# Creamos la solicitud de la clave publica al servidor 

	url = 'https://vega.ii.uam.es:8080/api/users/getPublicKey'
	args = {'userID': ID_emisor}
	r = requests.post(url, json=args)
	
	# r.text contiene la respuesta del servidor (la clave publica)

	clave_publica = RSA.import_key(r.text)

	cifrador = PKCS1_OAEP.new(clave_publica)

	return cifrador.decrypt(firma)

# Comprueba si la firma es valida o no

def firma_valida(firma_descifrada, mensaje):

	# Creamos el hash
	h = SHA256.new()
	# Lo aplicamos en el mensaje
	h.update(mensaje)

	if h.digest() == firma_descifrada:
		return true
	else:
		return false


# Funcion que se encarga de todo el proceso de desencriptacion

def desencriptar_all(mensaje, ID_emisor):

	# Separamos el mensaje cifrado por partes (primero va el sobre, luego iv y luego la firma y el mensaje cifrados)
	sobre = mensaje[0:AESCLEN]

	aux = AESCLEN+16
	iv = mensaje[AESCLEN:aux]

	aux2 = 100
	firma = mensaje[aux: aux2] # CUANTO OCUPA LA FIRMA????

	c_mensaje = mensaje[aux2:]

	clave = abrir_sobre(sobre)
	d_mensaje = desencriptar_AES(clave, iv, c_mensaje)
	d_firma = desencriptar_firma(firma, ID_emisor)

	if firma_valida(d_firma, d_mensaje):
		return d_mensaje
	else:
		print "La firma no es válida."
		return
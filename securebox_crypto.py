import securebox_files as files
import securebox_users as users
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from  Crypto.Util import Padding

IVLEN = 16
AESCLEN = 32
SLEN = 32


# 2 conceptos claros:
# Fichero: Referencia a archivo
# Mensaje: Contenido del fichero una vez leido


# Funciones para encriptar

# utiliza HASH y crea la firma 

def crear_firma(mensaje):
	# Creamos el hash
	h = SHA256.new()
	# Lo aplicamos en el mensaje
	h.update(mensaje)	

	clave_privada = RSA.import_key(open("clave_privada.dat", "r").read())
	cifrador = PKCS1_OAEP.new(clave_privada)
	return cifrador.encrypt(h.digest())


#Firma un archivo, sin encriptarlo con AES
def firmar_mensaje(mensaje):

	firma = crear_firma(mensaje)

	return firma + mensaje


def firmar_fichero(fichero):

	print "-> Firmando fichero " + fichero + " ..."

	with open(fichero, "r") as f:
		mensaje = f.read()
	
	mensaje_firmado = firmar_mensaje(mensaje)

	with open("signed_"+fichero, "w") as f:
		f.write(mensaje_firmado)

	print "-> OK: Fichero firmado satisfactoriamente"
	print "Fichero firmado: signed_" + fichero

	return

# cifra el mensaje+firma de manera simetrica usando AES
def encriptar_AES(mensaje, clave):

	iv = get_random_bytes(IVLEN)

	mensaje = Padding.pad(mensaje, 16)

	cifrado_aes = AES.new(clave, AES.MODE_CBC, iv)
	return iv + cifrado_aes.encrypt(mensaje)


# coge la clave del AES del anadir firma y la cifra con RSA con la clave publica del receptor
def crear_sobre(clave, ID_receptor, token):
	
	# Creamos la solicitud de la clave publica al servidor 
	print "-> Recuperando clave publica de ID {}...".format(ID_receptor)
	clave_publica = users.buscar_clave_publica(ID_receptor, token)

	if clave_publica == None:
		print "ERROR: No se ha encontrado un usuario con esa clave publica"
		return None
	
	#clave_publica = RSA.import_key(clave_publica_aux)

	print "-> OK: Clave encontrada Y ES ESTA WAAAAA: " + clave_publica

	# Encriptamos la clave del AES

	cifrador = PKCS1_OAEP.new(clave_publica)
	return cifrador.encrypt(clave)

def encriptar_mensaje(mensaje, ID_receptor, token):
		clave = get_random_bytes(AESCLEN)
		c_mensaje = encriptar_AES(mensaje, clave)
		sobre = crear_sobre(clave, ID_receptor, token)

		if sobre == None:
			print "ERROR: No se ha podido encriptar el fichero de forma correcta"
			return None

		return sobre + c_mensaje

#Esta funcion solo encripta un fichero, no utiliza para nada firma digital, pero si sobre. Se usa a nivel local.
def encriptar_fichero(fichero, ID_receptor, token):
	
	print "-> Encriptando el fichero " + fichero + " para el usuario " + ID_receptor +" ..."
	# Generamos la clave que usara AES y encriptamos con dicha clave
	with open(fichero, 'r') as f:
		mensaje = f.read()

	envelope = encriptar_mensaje(mensaje, ID_receptor, token) 

	with open("encrypted_" + fichero, 'w') as f_enc:
		f_enc.write(envelope)

	print "-> OK: Encriptado realizado satisfactoriamente"
	print "El fichero encriptado: encrypted_" + fichero
	return 

# Se encarga de todo el proceso de cifrar un mensaje

def firmar_y_encriptar_mensaje(mensaje, ID_receptor, token):

	print "-> Firmando..."

	mensaje_firmado = firmar_mensaje(mensaje)

 	print "-> OK: Fichero firmado satisfactoriamente"
 	print "-> Encriptando..."

 	mensaje_encriptado = encriptar_mensaje(mensaje, ID_receptor, token)
 	
 	print "-> OK: Fichero encriptado satisfactoriamente"		
 	return mensaje_encriptado

def firmar_y_encriptar(fichero, ID_receptor, token):
	print "Firmando y cifrando fichero " + fichero

	with open(fichero, "r") as f:
		mensaje = f.read()
	
	mensaje_encriptado = firmar_y_encriptar_mensaje(mensaje, ID_receptor, token)

 	with open("encsgn_" + fichero, 'w') as f:
		f.write(mensaje_encriptado)
 	
	print "Fichero encriptado y firmado: encsgn_" + fichero
 	return


# Funciones para desencriptar

# descifra la clave del AES con la clave privada del receptor
def abrir_sobre(c_clave):

	# Conseguimos la clave privada del usuario

	clave_privada = RSA.import_key(open("clave_privada.dat", "r").read())

	cifrador = PKCS1_OAEP.new(clave_privada)

	return cifrador.decrypt(c_clave)


# descifra AES
def desencriptar_AES(clave, iv, c_mensaje):

	cifrador = AES.new(clave, AES.MODE_CBC, iv)

	return Padding.unpad(cifrador.decrypt(c_mensaje), 16)

# Devuelve el hash, gracias a RSA con la clave publica del emisor

def desencriptar_firma(firma, ID_emisor, token):

	# Creamos la solicitud de la clave publica al servidor 

	clave_publica_aux = buscar_clave_publica(ID_receptor, token)

	if clave==ERROR:

		return ERROR

	clave_publica = RSA.import_key(clave_publica_aux)

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

def desencriptar_all(mensaje, ID_emisor, token):
	print "-> Analizando archivo..."
	# Separamos el mensaje cifrado por partes (primero va el sobre, luego iv y luego la firma y el mensaje cifrados)

	sobre = mensaje[0:AESCLEN]

	aux = AESCLEN+16

	iv = mensaje[AESCLEN:aux]

	aux2 = aux + SLEN

	firma = mensaje[aux: aux2]

	c_mensaje = mensaje[aux2:]

	clave = abrir_sobre(sobre)
	d_mensaje = desencriptar_AES(clave, iv, c_mensaje)
	d_firma = desencriptar_firma(firma, ID_emisor, token)

	if firma_valida(d_firma, d_mensaje):
		return d_mensaje

	else:
		print "-> ERROR: La firma no es valida. Fichero no confiable"
		return None


#funcion para probar cosillas, no necesaria
def desencriptar_fichero(mensaje, ID_emisor):

	# Separamos el mensaje cifrado por partes (primero va el sobre, luego iv y luego la firma y el mensaje cifrados)

	sobre = mensaje[0:AESCLEN]

	aux = AESCLEN+16

	iv = mensaje[AESCLEN:aux]

	c_mensaje = mensaje[aux+1:]

	clave = abrir_sobre(sobre)
	d_mensaje = desencriptar_AES(clave, iv, c_mensaje)

	with open("salidatest.txt", "w") as f:
		f.write(d_mensaje)
	
	return 
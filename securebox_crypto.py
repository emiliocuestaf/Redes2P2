import securebox_files as files
import securebox_users as users
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from  Crypto.Util import Padding
from Crypto.Signature import pkcs1_15



IVLEN = 16
RSALEN = 256
AESCLEN = 32


# 2 conceptos claros:
# Fichero: Referencia a archivo
# Mensaje: Contenido del fichero una vez leido


# Funciones para encriptar

# utiliza HASH y crea la firma 

def crear_firma(mensaje):

	# Creamos el hash
	h = SHA256.new(mensaje)

	clave_privada = RSA.import_key(open("clave_privada.dat", "r").read())
	cifrador = PKCS1_OAEP.new(clave_privada)
	s = pkcs1_15.new(clave_privada).sign(h)
	return s

#Firma un archivo, sin encriptarlo con AES
def firmar_mensaje(mensaje):

	firma = crear_firma(mensaje)

	return firma + mensaje


def firmar_fichero(fichero):
	# Conseguimos el nombre real del fichero, solo util si se trabaja con ficheros en otros directorios
	file_name = os.path.basename(fichero)

	print "-> Firmando fichero " + fichero + " ..."

	try:
		with open(fichero, "rb") as f:
			mensaje = f.read()
	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None

	mensaje_firmado = firmar_mensaje(mensaje)

	#Comprobamos que los directorios que necesitamos existen, y si no, los creamos.
	direc = "./files"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	direc = "./files/signed"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	file_path = "{}/{}".format(direc, file_name)

	with open(file_path, "w") as f:
		f.write(mensaje_firmado)

	print "-> OK: Fichero firmado satisfactoriamente"
	print "-> Fichero firmado en la ruta " + file_path

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
	clave_publica_aux = users.buscar_clave_publica(ID_receptor, token)

	if clave_publica_aux == None:
		print "-> ERROR: No se ha encontrado clave publica para el usuario."
		return None
	
	clave_publica = RSA.import_key(clave_publica_aux)

	print "-> OK: Clave encontrada"

	# Encriptamos la clave del AES

	cifrador = PKCS1_OAEP.new(clave_publica)
	return cifrador.encrypt(clave)

def encriptar_mensaje(mensaje, ID_receptor, token):
	clave = get_random_bytes(AESCLEN)
	c_mensaje = encriptar_AES(mensaje, clave)
	sobre = crear_sobre(clave, ID_receptor, token)

	if sobre == None:
		print "-> ERROR: No se ha podido encriptar el fichero de forma correcta"
		return None

	return sobre + c_mensaje

#Esta funcion solo encripta un fichero, no utiliza para nada firma digital, pero si sobre. Se usa a nivel local.
def encriptar_fichero(fichero, ID_receptor, token):
	
	# Conseguimos el nombre real del fichero, solo util si se trabaja con ficheros en otros directorios
	file_name = os.path.basename(fichero)

	print "-> Encriptando el fichero " + fichero + " para el usuario " + ID_receptor +" ..."
	# Generamos la clave que usara AES y encriptamos con dicha clave
	try:
		with open(fichero, 'rb') as f:
			mensaje = f.read()

	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None

	envelope = encriptar_mensaje(mensaje, ID_receptor, token) 

	if envelope == None:
		print "-> ERROR: se aborta el encriptado del fichero."
		return None

	#Comprobamos que los directorios que necesitamos existen, y si no, los creamos.
	direc = "./files"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	direc = "./files/encrypted"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	file_path = "{}/{}".format(direc, file_name)


	with open(file_path, 'w') as f_enc:
		f_enc.write(envelope)

	print "-> OK: Encriptado realizado satisfactoriamente"
	print "-> Fichero encriptado en la ruta " + file_path
	return 

# Se encarga de todo el proceso de cifrar un mensaje

def firmar_y_encriptar_mensaje(mensaje, ID_receptor, token):

	print "-> Firmando..."

	mensaje_firmado = firmar_mensaje(mensaje)

 	print "-> OK: Fichero firmado satisfactoriamente"
 	print "-> Encriptando..."

 	mensaje_encriptado = encriptar_mensaje(mensaje_firmado, ID_receptor, token)

 	if mensaje_encriptado == None:
 		print "-> ERROR: se aborta el encriptado del fichero."
		return None
 	
 	print "-> OK: Fichero encriptado satisfactoriamente"		
 	return mensaje_encriptado

def firmar_y_encriptar(fichero, ID_receptor, token):

	# Conseguimos el nombre real del fichero, solo util si se trabaja con ficheros en otros directorios
	file_name = os.path.basename(fichero)

	print "Firmando y cifrando fichero {} para el receptor #{}...".format(fichero, ID_receptor)

	try:
		with open(fichero, "rb") as f:
			mensaje = f.read()
	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None
	
	mensaje_encriptado = firmar_y_encriptar_mensaje(mensaje, ID_receptor, token)

	if mensaje_encriptado == None:
		return None

	direc = "./files"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	direc = "./files/signed_and_encrypted"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	file_path = "{}/{}".format(direc, file_name)

 	with open(file_path, 'wb') as f:
		f.write(mensaje_encriptado)
 	
	print "-> Fichero encriptado y firmado en la ruta: " + file_path
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

# Comprueba si la firma es valida o no

def firma_valida(firma, mensaje, ID_emisor, token):

	# Creamos el hash
	h = SHA256.new(mensaje)

	# Creamos la solicitud de la clave publica al servidor 

	clave_publica_aux = users.buscar_clave_publica(ID_emisor, token)

	if clave_publica_aux==None:
		print "-> ERROR: no se puede comprobar la firma."
		return None

	clave_publica = RSA.import_key(clave_publica_aux)

	try:
		pkcs1_15.new(clave_publica).verify(h, firma)
	except (ValueError, TypeError):
		print "-> ERROR: La firma no es valida. Fichero no confiable"
		return False

	print "-> La firma es valida. Fichero confiable"

	return True

# Funcion que se encarga de todo el proceso de desencriptacion

def desencriptar_all(mensaje , ID_emisor, token):
	print "-> Analizando archivo..."
	# Separamos el mensaje cifrado por partes (primero va el sobre, luego iv y luego la firma y el mensaje cifrados)

	aux = RSALEN+IVLEN

	sobre = mensaje[0:RSALEN]
	iv = mensaje[RSALEN:aux]
	c_firma_y_mensaje = mensaje[aux:]

	print "-> Abriendo sobre..."
	
	clave = abrir_sobre(sobre)

	print "-> OK"

	print "-> Desencriptado AES..."

	d_firma_y_mensaje = desencriptar_AES(clave, iv, c_firma_y_mensaje)

	print "-> OK"

	d_firma = d_firma_y_mensaje[0:RSALEN]
	d_mensaje = d_firma_y_mensaje[RSALEN:]

	print "-> Validando firma..."
	validar = firma_valida(d_firma, d_mensaje, ID_emisor, token)
	
	if validar == True:
		print "-> OK"
		return d_mensaje
	elif validar == None:
		print "-> ERROR: abortamos proceso de desencriptado."
		return None

	print "-> ERROR"
	return None
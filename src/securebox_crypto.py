########
# REDES 2 - PRACTICA 2
# FICHERO: securebox_crypto.py
# DESCRIPCION: Fichero que define las funciones para cifrar y descifrar ficheros
# AUTORES: 
#	* Luis Carabe Fernandez-Pedraza 
#	* Emilio Cuesta Fernandez
# LAST-MODIFIED: 20-3-2018
########

import securebox_files as files
import securebox_users as users
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from  Crypto.Util import Padding
from Crypto.Signature import pkcs1_15



# Constantes que definen ciertas longitudes (en bytes)

IVLEN = 16 # Longitud del IV
RSALEN = 256 # Longitud del mensaje cifrado con RSA
AESCLEN = 32 # Longitud de la clave de AES




# Funciones para encriptar

#######
# FUNCION: crear_firma(mensaje)
# ARGS_IN: mensaje - el mensaje a firmar
# DESCRIPCION: crea la firma de un mensaje
# ARGS_OUT: devuelve la firma creada
#######
 

def crear_firma(mensaje):

	# Creamos el hash, del tipo SHA256

	h = SHA256.new(mensaje)

	# Cogemos la clave privada del fichero local y creamos el cifrador de RSA
	clave_privada = RSA.import_key(open("key/clave_privada.dat", "r").read())
	cifrador = PKCS1_OAEP.new(clave_privada)

	# Firmamos y devolvemos la firma

	s = pkcs1_15.new(clave_privada).sign(h)
	return s

#######
# FUNCION: firmar_mensaje(mensaje)
# ARGS_IN: mensaje - el mensaje a firmar
# DESCRIPCION: crea la firma de un mensaje y lo concatena con el mensaje original
# ARGS_OUT: devuelve la firma creada + el mensaje sin modificar
#######

def firmar_mensaje(mensaje):

	# Firmamos y devolvemos la firma con el mensaje

	firma = crear_firma(mensaje)
	return firma + mensaje

#######
# FUNCION: firmar_fichero(fichero)
# ARGS_IN: fichero - el fichero para firmar
# DESCRIPCION: Funcion para firmar un fichero, util para cuando se quiere firmar sin encriptar
# ARGS_OUT: None en caso de error, crea el fichero firmado en caso contrario, sin devolver nada
#######


def firmar_fichero(fichero):

	# Conseguimos el nombre real del fichero, solo util si se trabaja con ficheros en otros directorios

	file_name = os.path.basename(fichero)

	print "-> Firmando fichero " + fichero + " ..."

	# Abrimos el fichero y leemos su contenido, controlando que exista

	try:
		with open(fichero, "rb") as f:
			mensaje = f.read()
	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None

	# Firmamos el mensaje

	mensaje_firmado = firmar_mensaje(mensaje)

	# Comprobamos que los directorios que necesitamos (donde guardamos los ficheros firmados) existen , y si no, los creamos

	direc = "./files"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	direc = "./files/signed"
	if os.path.exists(direc) == False:
		os.mkdir(direc)

	# Creamos la ruta de destino del fichero y guardamos la firma en dicho destino

	file_path = "{}/{}".format(direc, file_name)
	with open(file_path, "w") as f:
		f.write(mensaje_firmado)

	print "-> OK: Fichero firmado satisfactoriamente"
	print "-> Fichero firmado en la ruta " + file_path

	return

#######
# FUNCION: encriptar_AES(mensaje, clave)
# ARGS_IN: mensaje - el mensaje que vamos a cifrar
#		   clave - la clave que usara AES para cifrar, en este caso, de 32 bytes	
# DESCRIPCION: funcion que cifra un mensaje de manera simetrica con AES en modo CBC
# ARGS_OUT: el vector de inicializacion concatenado con el mensaje cifrado
#######

def encriptar_AES(mensaje, clave):

	# Generamos el iv de manera aleatoria

	iv = get_random_bytes(IVLEN)

	# Como vamos a leer bloques de 16 bytes, necesitamos ajustar el tamanio del mensaje con pad

	mensaje = Padding.pad(mensaje, 16)

	# Ciframos con AES en modo CBC usando el iv generado

	cifrado_aes = AES.new(clave, AES.MODE_CBC, iv)
	return iv + cifrado_aes.encrypt(mensaje)

#######
# FUNCION: crear_sobre(clave, ID_receptor, token)
# ARGS_IN: clave - la clave usada en AES que se cifrara con RSA
#		   ID_receptor - el id del receptor del fichero que estamos enviando
#		   token - necesario para enviar a SecureBox la peticion para conseguir la clave publica	
# DESCRIPCION: funcion que cifra la clave usada en AES con RSA usando la clave publica
#				 del usuario receptor, creando asi el sobre digital
# ARGS_OUT: el sobre digital (la clave cifrada)
#######

def crear_sobre(clave, ID_receptor, token):

	# Creamos la solicitud de la clave publica al servidor y comprobamos que no sea None

	print "-> Recuperando clave publica de ID {}...".format(ID_receptor)
	clave_publica_aux = users.buscar_clave_publica(ID_receptor, token)

	if clave_publica_aux == None or not clave_publica_aux:
		print "-> ERROR: No se ha encontrado clave publica para el usuario."
		return None

	# Importamos el retorno de la solicitud como clave para RSA
	
	clave_publica = RSA.import_key(clave_publica_aux)

	print "-> OK: Clave encontrada"

	# Encriptamos la clave del AES y lo devolvemos

	cifrador = PKCS1_OAEP.new(clave_publica)
	return cifrador.encrypt(clave)

#######
# FUNCION: encriptar_mensaje(mensaje, ID_receptor, token)
# ARGS_IN: mensaje - el mensaje que vamos a cifrar
#		   ID_receptor - el id del receptor del fichero que estamos enviando
#		   token - necesario para enviar a SecureBox la peticion para conseguir la clave publica
# DESCRIPCION: funcion que cifra un mensaje, aplicando AES y creando el sobre digital
# ARGS_OUT: el mensaje cifrado con AES, precedido por el sobre digital
#######

def encriptar_mensaje(mensaje, ID_receptor, token):

	# Generamos aletoriamente la clave de 32 bytes que se usara para cifrar con AES
	clave = get_random_bytes(AESCLEN)

	# Ciframos el mensaje con AES
	c_mensaje = encriptar_AES(mensaje, clave)

	# Creamos el sobre, comprobando si es None
	sobre = crear_sobre(clave, ID_receptor, token)

	if sobre == None:
		print "-> ERROR: No se ha podido encriptar el fichero de forma correcta"
		return None

	# Devolvemos el mensaje cifrado precedido por el sobre digital

	return sobre + c_mensaje

#######
# FUNCION: encriptar_fichero(fichero, ID_receptor, token)
# ARGS_IN: fichero - el fichero que vamos a cifrar
#		   ID_receptor - el id del receptor del fichero que estamos enviando
#		   token - necesario para enviar a SecureBox la peticion para conseguir la clave publica
# DESCRIPCION: funcion que cifra un fichero, aplicando AES y creando el sobre digital, usada
#				para cuando el usuario solo quiera encriptar un fichero, sin firmarlo
# ARGS_OUT: None en caso de error, crea el fichero cifrado en caso contrario, sin devolver nada
#######

def encriptar_fichero(fichero, ID_receptor, token):
	
	# Conseguimos el nombre real del fichero, solo util si se trabaja con ficheros en otros directorios

	file_name = os.path.basename(fichero)

	print "-> Encriptando el fichero " + fichero + " para el usuario " + ID_receptor +" ..."

	# Abrimos el fichero y guardamos su contenido, controlando excepciones

	try:
		with open(fichero, 'rb') as f:
			mensaje = f.read()

	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None

	# Guardamos el sobre y el mensaje encriptado con AES

	envelope = encriptar_mensaje(mensaje, ID_receptor, token) 

	if envelope == None:
		print "-> ERROR: se aborta el encriptado del fichero."
		return None

	# Comprobamos que los directorios que necesitamos (donde guardamos los ficheros
	# que encriptamos pero no firmamos) existen, y si no, los creamos

	direc = "./files"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	direc = "./files/encrypted"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	file_path = "{}/{}".format(direc, file_name)

	# Creamos la ruta de destino del fichero y guardamos el sobre + mensaje cifrado en dicho destino

	with open(file_path, 'w') as f_enc:
		f_enc.write(envelope)

	print "-> OK: Encriptado realizado satisfactoriamente"
	print "-> Fichero encriptado en la ruta " + file_path
	return

#######
# FUNCION: firmar_y_encriptar_mensaje(mensaje, ID_receptor, token)
# ARGS_IN: mensaje - el mensaje que vamos a cifrar
#		   ID_receptor - el id del receptor del fichero que estamos enviando
#		   token - necesario para enviar a SecureBox la peticion para conseguir la clave publica
# DESCRIPCION: funcion que se encarga de todo el proceso de cifrar un mensaje:
#				firmarlo, encriptarlo y crear el sobre
# ARGS_OUT: None en caso de error, el mensaje firmado y cifrado por completo
#######


def firmar_y_encriptar_mensaje(mensaje, ID_receptor, token):

	print "-> Firmando..."

	# Llamamos a la funcion que firma el mensaje y concatena la firma con el mensaje sin cifrar
	mensaje_firmado = firmar_mensaje(mensaje)

 	print "-> OK: Fichero firmado satisfactoriamente"
 	print "-> Encriptando..."

 	# Encriptamos el mensaje junto con la firma, comprobamos si es None

 	mensaje_encriptado = encriptar_mensaje(mensaje_firmado, ID_receptor, token)

 	if mensaje_encriptado == None:
 		print "-> ERROR: se aborta el encriptado del fichero."
		return None

	# Si todo se ha acontecido de manera satisfactoria, devolvemos el mensaje cifrado
 	
 	print "-> OK: Fichero encriptado satisfactoriamente"		
 	return mensaje_encriptado

 #######
# FUNCION: firmar_y_encriptar(fichero, ID_receptor, token)
# ARGS_IN: fichero - el fichero que vamos a cifrar
#		   ID_receptor - el id del receptor del fichero que estamos enviando
#		   token - necesario para enviar a SecureBox la peticion para conseguir la clave publica
# DESCRIPCION: funcion que se encarga de todo el proceso de cifrar un fichero:
#				firmarlo, encriptarlo y crear el sobre
# ARGS_OUT: None en caso de error, crea el fichero cifrado y firmado en caso contrario, sin devolver nada
#######

def firmar_y_encriptar(fichero, ID_receptor, token):

	# Conseguimos el nombre real del fichero, solo util si se trabaja con ficheros en otros directorios

	file_name = os.path.basename(fichero)

	print "Firmando y cifrando fichero {} para el receptor #{}...".format(fichero, ID_receptor)

	# Abrimos el fichero y leemos su contenido, controlando excepciones

	try:
		with open(fichero, "rb") as f:
			mensaje = f.read()
	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None

	# Firmamos y encriptamos el contenido del fichero, comprobando que la respuesta no sea None
	
	mensaje_encriptado = firmar_y_encriptar_mensaje(mensaje, ID_receptor, token)

	if mensaje_encriptado == None:
		return None

	# Comprobamos que los directorios que necesitamos (donde guardamos los ficheros
	# que encriptamos y firmamos) existen, y si no, los creamos

	direc = "./files"
	if os.path.exists(direc) == False:
		os.mkdir(direc)
	direc = "./files/signed_and_encrypted"
	if os.path.exists(direc) == False:
		os.mkdir(direc)

	# Creamos la ruta de destino del fichero y guardamos el mensaje cifrado y firmado en dicho destino

	file_path = "{}/{}".format(direc, file_name)

 	with open(file_path, 'wb') as f:
		f.write(mensaje_encriptado)
 	
	print "-> Fichero encriptado y firmado en la ruta: " + file_path
 	return


# Funciones para descifrar

#######
# FUNCION: abrir_sobre(c_clave)
# ARGS_IN: c_clave - la clave que queremos descifrar
# DESCRIPCION: descifra el sobre digital, es decir, descifra usando RSA 
#				con la clave privada del usuario, la clave que necesita AES
# ARGS_OUT: la clave descifrada
#######

def abrir_sobre(c_clave):
 
	# Conseguimos la clave privada del usuario y la importamos como clave de RSA
	clave_privada = RSA.import_key(open("key/clave_privada.dat", "r").read())

	# Aplicamos RSA para descifrar la clave

	cifrador = PKCS1_OAEP.new(clave_privada)
	return cifrador.decrypt(c_clave)

#######
# FUNCION: desencriptar_AES(clave, iv, c_mensaje)
# ARGS_IN: c_mensaje - el mensaje que vamos a descifrar
#		   clave - la clave que usara AES para descifrar, en este caso, de 32 bytes	
#		   iv - el vector de inicialiciacion necesario para AES
# DESCRIPCION: funcion que descifra un mensaje de manera simetrica con AES en modo CBC
# ARGS_OUT: el mensaje descifrado
#######

def desencriptar_AES(clave, iv, c_mensaje):

	# Desciframos el mensaje con AES en modo CBC, gracias al iv y la clave

	cifrador = AES.new(clave, AES.MODE_CBC, iv)

	# Necesitamos hacer unpad, ya que como dijimos en la funcion que cifraba AES, CBC encripta por bloques
	# y es necesario que el mensaje vuelva a su longitud original

	return Padding.unpad(cifrador.decrypt(c_mensaje), 16)

#######
# FUNCION: firma_valida(firma, mensaje, ID_emisor, token)
# ARGS_IN: firma - firma a verificar
#	  	   mensaje - el mensaje que usamos para verificar la firma
#		   ID_emisor - el id del emisor del fichero que estamos recibiendo
#		   token - necesario para enviar a SecureBox la peticion para conseguir la clave publica
# DESCRIPCION: funcion que se encarga de verificar la firma, aplicando el hash al mensaje para 
#				comprobar si se corresponde con la firma recibida
# ARGS_OUT: None en caso de error, False en caso de que la firma no sea valida, True en caso de que si
#######

def firma_valida(firma, mensaje, ID_emisor, token):

	# Creamos el hash del mensaje
	h = SHA256.new(mensaje)

	# Creamos la solicitud de la clave publica al servidor y comprobamos que no sea None

	clave_publica_aux = users.buscar_clave_publica(ID_emisor, token)

	if clave_publica_aux==None:
		print "-> ERROR: no se puede comprobar la firma."
		return None

	# Importamos la respuesta a dicha solicitud como clave de RSA

	clave_publica = RSA.import_key(clave_publica_aux)

	# Comprobamos la validez de la firma

	try:
		pkcs1_15.new(clave_publica).verify(h, firma)
	except (ValueError, TypeError):
		print "-> ERROR: La firma no es valida. Fichero no confiable"
		return False

	print "-> La firma es valida. Fichero confiable"

	return True

#######
# FUNCION: desencriptar_all(mensaje, ID_emisor, token)
# ARGS_IN: mensaje - el mensaje cifrado que queremos descifrar
#		   ID_emisor - el id del emisor del fichero que estamos recibiendo
#		   token - necesario para enviar a SecureBox la peticion para conseguir la clave publica
# DESCRIPCION: funcion que se encarga de todo el proceso de descifrado:
#				abrir sobre, descifrar AES y validar firma
# ARGS_OUT: None en caso de error, el mensaje descifrado en caso contrario
#######

def desencriptar_all(mensaje , ID_emisor, token):
	print "-> Analizando archivo..."

	# Separamos el mensaje cifrado por partes (primero va el sobre, luego iv y luego la firma y el mensaje cifrados)

	aux = RSALEN+IVLEN

	sobre = mensaje[0:RSALEN]
	iv = mensaje[RSALEN:aux]
	c_firma_y_mensaje = mensaje[aux:]

	print "-> Abriendo sobre..."
	
	# Abrimos el sobre
	clave = abrir_sobre(sobre)

	print "-> OK"

	print "-> Desencriptado AES..."

	# Desciframos AES
	d_firma_y_mensaje = desencriptar_AES(clave, iv, c_firma_y_mensaje)

	print "-> OK"

	# Separamos firma y mensaje descifrado (la firma ocupa 256 bytes)

	d_firma = d_firma_y_mensaje[0:RSALEN]
	d_mensaje = d_firma_y_mensaje[RSALEN:]

	print "-> Validando firma..."

	# Validamos firma
	validar = firma_valida(d_firma, d_mensaje, ID_emisor, token)
	
	if validar == True:
		print "-> OK"
		return d_mensaje
	elif validar == None:
		print "-> ERROR: abortamos proceso de desencriptado."
		return None

	print "-> ERROR"
	return None
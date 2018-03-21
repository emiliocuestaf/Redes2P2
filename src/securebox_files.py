########
# REDES 2 - PRACTICA 2
# FICHERO: securebox_files.py
# DESCRIPCION: Fichero que define las funciones para manejar ficheros
# AUTORES: 
#	* Luis Carabe Fernandez-Pedraza 
#	* Emilio Cuesta Fernandez
# LAST-MODIFIED: 20-3-2018
########

import securebox_crypto as crypto
import requests
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from shutil import copyfile


#######
# FUNCION: codigos_error(error, descripcion)
# ARGS_IN: error - el codigo del error
#		   descripcion - la descripcion del error
# DESCRIPCION: imprime un mensaje con el error HTTP correspondiente
#######

def codigos_error(error, descripcion):

	# Comparamos cada error e imprimimos su descripcion
	if error == "TOK1":
		print "-> ERROR: " + descripcion
	elif error == "TOK2":
		print "-> ERROR: " + descripcion
	elif error == "TOK3":
		print "-> ERROR: " + descripcion
	elif error == "FILE1":
		print "-> ERROR: " + descripcion
	elif error == "FILE2":
		print "-> ERROR: " + descripcion
	elif error == "FILE3":
		print "-> ERROR: " + descripcion
	elif error == "ARGS1":
		print "-> ERROR: " + descripcion
	else:
		print "-> ERROR: indefinido."
	return

#######
# FUNCION: subir_fichero(fichero, token)
# ARGS_IN: fichero - el fichero a subir al servidor
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: sube un fichero ya cifrado al servidor
# ARGS_OUT: None si hay error, el id del fichero subido en caso contrario
#######

def subir_fichero(fichero, token):

	# Abrimos el fichero controlando excepciones

	try:
		with open(fichero, "r") as f:	
			# Escritura de la peticion de la subida
			url = 'https://vega.ii.uam.es:8080/api/files/upload'
			headers = {'Authorization': "Bearer " + token}

			# Envio de solicitud, se almacena respuesta en r
			r = requests.post(url, headers=headers, files={'ufile':f})
	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None

	# Si el codigo HTTP es 200, devolvemos el id del fichero, teniendo cuidado con el formato json

	if r.status_code == 200 :
		dic = r.json()
		file_id = dic['file_id']
		file_size = dic['file_size']
		return file_id

	# Si no, imprimimos el correspondiente error
	else:
		codigos_error(r.json()['error_code'], r.json()['description'])
		return None
	return

#######
# FUNCION: cifrar_y_subir_fichero(fichero, ID_receptor, token)
# ARGS_IN: fichero - el fichero a encriptar y subir al servidor
#		   ID_receptor - el id del receptor del mensaje
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: sube un fichero al servidor tras encriptarlo
# ARGS_OUT: None si hay error, nada en caso contrario
#######


def cifrar_y_subir_fichero(fichero, ID_receptor, token):

	# Conseguimos el nombre real del fichero, solo util si se trabaja con ficheros en otros directorios
	
	file_name = os.path.basename(fichero)

	print "-> Cifrando y subiendo el fichero " + fichero + "..."	

	# Abrimos el fichero para leer su contenido, controlando excepciones

	try:
		with open(fichero, "r") as f:
			mensaje = f.read()
	except EnvironmentError:
		print "-> ERROR: No se puede abrir el fichero (no existe)."
		return None

	# Ciframos el mensaje, comprobando si es None

	mensaje_encriptado = crypto.firmar_y_encriptar_mensaje(mensaje, ID_receptor, token)

	if mensaje_encriptado == None:
		print "-> ERROR: se aborta la subida del fichero."
		return

	# Guardamos el mensaje encriptado en otro fichero
	
	with open(file_name, "w") as f:
		f.write(mensaje_encriptado)

	print "-> Subiendo fichero " + fichero	

	# Subimos el fichero, controlando excepciones

	try:
		file_id = subir_fichero(file_name, token)

	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	# Comprobamos si hay errores, en cualquier caso, borramos el fichero auxiliar donde guardabamos el fichero encriptado

	if file_id == None:
		os.remove(file_name)
		print "-> ERROR: EL fichero no se ha podido subir correctamente"
		return
	os.remove(file_name)
	print "-> OK"
	print "-> Subida realizada satisfactoriamente, ID del fichero " + file_id
	return 

#######
# FUNCION: descargar_fichero(id_fichero, ID_emisor, token)
# ARGS_IN: id_fichero - el id del fichero a descargar
#		   ID_emisor - el id del emisor del mensaje
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: sube un fichero al servidor tras encriptarlo
# ARGS_OUT: None si hay error, nada en caso contrario
#######

# Funcion que descarga un fichero del sistema, devolviendolo en binario

def descargar_fichero(id_fichero, ID_emisor, token):

	print "-> Descargando el fichero " + id_fichero + "..."

	# Escritura de la peticion de la descarga

	url = 'https://vega.ii.uam.es:8080/api/files/download'
	headers = {'Authorization': "Bearer " + token}
	args = {'file_id': id_fichero}
	
	# Envio de solicitud, se almacena respuesta en r, controlando excepciones
	try:
		r = requests.post(url, headers=headers, json=args)

	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	# Devolvemos el fichero en binario solo si la respuesta tiene un codigo 200

	if r.status_code == 200 :

		print "-> OK: Descarga correcta"

		# Buscamos la cabecera que contiene el nombre del archivo
		# Esto solo lo hacemos si sc = 200 porque si no no tenemos garantia cd que exista la cabecera

		headers = r.headers
		file_name = "{}".format(headers['content-disposition'].split('"')[1])
	
		#Comprobamos que los directorios que necesitamos (donde guardamos los ficheros descargados) existen, y si no, los creamos

		direc = "./files"
		if os.path.exists(direc) == False:
			os.mkdir(direc)
		direc = "./files/downloads"
		if os.path.exists(direc) == False:
			os.mkdir(direc)

		# Guardamos la direccion final del fichero descargado y el contenido del fichero encriptado

		file_path = "{}/{}".format(direc, file_name)
		mensaje_cifrado = r.content

		# Desciframos el mensaje, controlando excepciones
		
		try:	
			mensaje_descifrado = crypto.desencriptar_all(mensaje_cifrado, ID_emisor, token)
		except (ValueError, TypeError):
			print "-> ERROR: No se ha podido completar la decodificacion. Aborting"
			return
	
		if mensaje_descifrado == None:
			print "-> ERROR: Abortamos bajada del fichero."
			return

		# Si el mensaje se ha descifrado correctamente, lo escribimos en un fichero, con la ruta previamente calculada

		with open(file_path, "w") as f:
			f.write(mensaje_descifrado)
		
		print "-> OK: El fichero se ha descargado correctamente en: {}".format(file_path) 
		return

	# Imprimimos el mensaje de error de HTTP

	else:
		codigos_error(r.json()['error_code'], r.json()['description'])
		print "-> ERROR: El fichero no se ha podido descargar."
		return None

	return

#######
# FUNCION: listar_ficheros(token)
# ARGS_IN: token - necesario para realizar peticiones al servidor
# DESCRIPCION: funcion que lista todos los ficheros pertenecientes a un usuario
# ARGS_OUT: None si hay error, en caso contrario no se devuelve nada
#######


def listar_ficheros(token):
	print "-> Listando ficheros..."

	# Escritura de la peticion de la lista de ficheros
	url = 'https://vega.ii.uam.es:8080/api/files/list'
	headers = {'Authorization': "Bearer " + token}

	# Realizamos la peticion, controlando excepciones

	try:
		r = requests.post(url, headers=headers)
	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	#  Imprimimos la lista de archivos en el caso en el que la respuesta tenga codigo 200

	if r.status_code == 200:
		d =  r.json()
		print "-> {} ficheros encontrados:".format(d['num_files'])
		flist = d['files_list']
		count = 0
		# Iteramos todos los ficheros de la lista
		for item in flist:
			print "-> [{}] ID: {}, fileName: {}".format(count+1, item['fileID'], item['fileName'])
			count += 1
		print "OK: Ficheros mostrados correctamente"
		return 

	# En caso de error, imprimimos su descripcion
	else:
		codigos_error(r.json()['error_code'], r.json()['description'])
		print "ERROR: No se han podido mostrar todos los ficheros satisfactoriamente"
		return 


#######
# FUNCION: borrar_fichero(id_fichero, token)
# ARGS_IN: id_fichero - id del fichero a eliminar
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: funcion que borra un fichero del servidor
# ARGS_OUT: None si hay error, en caso contrario no se devuelve nada
#######

def borrar_fichero(id_fichero, token):
	print "-> Borrando el fichero con ID "+ id_fichero + "..."

	# Escritura de la peticion de el borrado del fichero
	url = 'https://vega.ii.uam.es:8080/api/files/delete'
	headers = {'Authorization': "Bearer " + token}
	args = {'file_id': id_fichero}

	# Enviamos la peticion de borrado al servidor, controlando excepciones

	try:
		r = requests.post(url, headers=headers, json=args)
	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	# Si la respuesta HTTP no tiene de codigo 200, imprimimos el mensaje de error

	if r.status_code == 200:
		print "-> OK: El fichero " + r.json()['file_id'] + "ha sido borrado satisfactoriamente"
		return 
	else:
		codigos_error(r.json()['error_code'], r.json()['description'])
		print "-> ERROR: no ha sido posible borrar el fichero correctamente"
		return 


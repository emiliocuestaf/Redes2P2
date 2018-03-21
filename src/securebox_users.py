########
# REDES 2 - PRACTICA 2
# FICHERO: securebox_users.py
# DESCRIPCION: Fichero que define las funciones para manejar usuarios
# AUTORES: 
#	* Luis Carabe Fernandez-Pedraza 
#	* Emilio Cuesta Fernandez
# LAST-MODIFIED: 20-3-2018
########


from Crypto.PublicKey import RSA
import requests
import os

# Ruta del fichero de la clave privada
key_path = "./key/"

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
	elif error == "USER_ID1":
		print "-> ERROR: " + descripcion
	elif error == "USER_ID2":
		print "-> ERROR: " + descripcion
	elif error == "USER_ID3":
		print "-> ERROR: " + descripcion
	elif error == "ARGS1":
		print "-> ERROR: " + descripcion
	else:
		print "-> ERROR: indefinido."
	return

#######
# FUNCION: registro(nombre, email, alias, token)
# ARGS_IN: nombre - nombre del usuario que se registra
#		   email - email del usuario que se registra
#		   alias - alias del usuario que se registra
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: almacena un usuario, genera las claves y guarda su clave publica en el servidor
# 				y la privada de forma local
# ARGS_OUT: None si hay error, nada en caso contrario
#######

def registro(nombre, email, alias, token):

	#Generacion de claves para RSA
	key = RSA.generate(2048)
	#Se usa PEM debido a criterios de la practica
	privateKey = key.exportKey('PEM')
	publicKey = key.publickey().exportKey('PEM')

	print "-> Registrando usuario con:\n\t*Nombre: {}\n\t*Email: {}\n\t*Alias: {}".format(nombre, email, alias)
	print "-> ..."
	#Escritura de la peticion de registro
	url = 'https://vega.ii.uam.es:8080/api/users/register'
	headers = {'Authorization': "Bearer " + token}
	args = {'nombre': nombre, 'email': email,'alias': alias, 'publicKey': publicKey}
	
	# Envio de solicitud de alta de usuario, se almacena respuesta en r, controlando excepciones
	try:
		r = requests.post(url, headers=headers, json=args)
	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	#Guardamos la clave privada en un fichero solo si la respuesta tiene un codigo 200
	if r.status_code == 200 :

		# Si no existe el directorio donde guardamos la clave, lo creamos
		if os.path.exists(key_path) == False:
			os.mkdir(key_path)

		# Escribimos la clave privada en el fichero

		with open(key_path + "clave_privada.dat", "wb") as key_file:
			key_file.write(privateKey)
		

		# Las proximas lineas sirven para conseguir el ID del usuario, es necesaria una llamada auxiliar a search

		r2 = buscar_identidad_aux(data_search=email, token= token)

		# Buscamos en la lista de usuarios con ese email el que se ha creado el ultimo, para eso debemos mirar el timestamp mas alto

		d =  r2.json()
		maxts = -1000
		currentID = None
		for item in d:
			aux = item['ts']
			if aux > maxts :
				maxts = aux
				currentID = item['userID'] 

		# Se imprimen todos los credenciales obtenidos por pantalla
			
		print "-> OK\n-> Estos son sus credenciales:"
		print "-> \t*Nombre: {}".format(r.json()['nombre'])
		print "-> \t*ts: {}".format(r.json()['ts'])
		print "-> \t*UserID: {}".format(currentID)

		# Se guardan estos credenciales en register.dat para que sean accesibles para el usuario

		with open("register.dat", "w") as reg_file:
			string = "Este archivo contiene los datos del registro del ultimo usuario:\nNombre: {}\nEmail: {}\nAlias: {}\nUserID: {}".format(r.json()['nombre'], email, alias, currentID)
			reg_file.write(string)

	# Si hay error de HTTP, lo imprimimos

	else :
		codigos_error(r.json()['error_code'], r.json()['description'])
		print "-> ERROR: El usuario no se ha podido registrar."

	return


#######
# FUNCION: buscar_clave_publica(userID, token)
# ARGS_IN: userID - ID del usuario al que queremos consultar su clave publica
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: busca la clave publica de un usuario
# ARGS_OUT: None si hay error, la clave publica en caso contrario
#######

def buscar_clave_publica(userID, token):

	#Escritura de la peticion de clave publica
	url = 'https://vega.ii.uam.es:8080/api/users/getPublicKey'
	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}

	# Peticion al servidor, controlando excepciones

	try:
		r = requests.post(url, headers=headers, json=args)
	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	# Si la respuesta de HTTP tiene como codigo 200, devolvemos la clave publica del usuario, si no, imprimimos el error

	if r.status_code == 200:
		return r.json()['publicKey']
	else:
		codigos_error(r.json()['error_code'], r.json()['description'])
		print "-> ERROR. No se ha encontrado la clave publica del usuario {}".format(userID)
		return None

#######
# FUNCION: buscar_identidad_aux(data_search, token)
# ARGS_IN: data_search - parametro que vamos a usar para buscar
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: busca el parametro pasado en la informacion contenida en el servidor, 
#				funcion auxiliar que sirve para buscar el id cuando creamos un usuario
# ARGS_OUT: None si hay error, la respuesta del servidor en caso contrario
#######


def buscar_identidad_aux(data_search, token):
	
	# Escritura de la peticion de busqueda de usuario
	url = 'https://vega.ii.uam.es:8080/api/users/search'
	headers = {'Authorization': "Bearer " + token}
	args = {'data_search': data_search}

	# Realizamos la peticion, controlando excepciones

	try:
		r = requests.post(url, headers=headers, json=args)

	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	# Devolvemos la respuesta del servidor

	return r

#######
# FUNCION: buscar_identidad(data_search, token)
# ARGS_IN: data_search - parametro que vamos a usar para buscar
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: busca el parametro pasado en la informacion contenida en el servidor
# ARGS_OUT: None si hay error, nada en caso contrario
#######

def buscar_identidad(data_search, token):

	print "-> Buscando usuario {} en el servidor...".format(data_search)

	# Escritura de la peticion de busqueda de usuario
	url = 'https://vega.ii.uam.es:8080/api/users/search'
	headers = {'Authorization': "Bearer " + token}
	args = {'data_search': data_search}

	# Realizamos la peticion, controlando excepciones

	try:
		r = buscar_identidad_aux(data_search=data_search, token= token)
	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	# Si la respuesta HTTP es correcta, listamos los usuarios encontrados
	if r.status_code == 200:
		print "-> OK"
		d =  r.json()
		print "-> {} usuarios encontrados".format(len(d))
		count = 0
		# Iteramos la lista de usuarios devuelta por el servidor
		for item in d:
			print "[{}] {}, {}, ID: {}".format(count+1, d[count]['nombre'], d[count]['email'], d[count]['userID'])
			count += 1

	# Si hay ERROR, lo imprimimos
	else:
		codigos_error(r.json()['error_code'], r.json()['description'])
		print "-> ERROR: no se han encontrado usuarios que concuerden con su busqueda"

	return

#######
# FUNCION: borrar_identidad(userID, token)
# ARGS_IN: userID - ID del usuario que queremos borrar
#		   token - necesario para realizar peticiones al servidor
# DESCRIPCION: borra una identidad si y solo si esta ha sido creada por el propio usuario
# ARGS_OUT: None si hay error, nada en caso contrario
#######

def borrar_identidad(userID, token):

	print "Borrando usuario {} del servidor...".format(userID)

	# Escritura de la peticion de borrado de usuario

	url = 'https://vega.ii.uam.es:8080/api/users/delete'
	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}

	# Realizamos la peticion, controlando excepciones

	try:
		r = requests.post(url, headers=headers, json=args)

	except requests.ConnectionError:
		print "-> ERROR: no hay conexion"
		return None

	# Si la respuesta HTTP es correcta informamos al usuario

	if r.status_code == 200:
		print "-> OK"
		print "-> El usuario con ID {} ha sido eliminado satisfactoriamente o no existia de antemano".format(r.json()['userID'])
		
	# Si hay ERROR, lo imprimimos
	else:
		codigos_error(r.json()['error_code'], r.json()['description'])
		print "-> ERROR: no se ha podido borrar el usuario"
	return	


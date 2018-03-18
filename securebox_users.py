from Crypto.PublicKey import RSA
import requests

# almacena un usuario, genera las claves y guarda su clave publica en el servidor
# y la privada de forma local.
def registro(nombre, email, alias, token):

	#Generacion de claves para RSA
	key = RSA.generate(2048)
	#Se usa PEM porque lo dice el enunciado.
	privateKey = key.exportKey('PEM')
	publicKey = key.publickey().exportKey('PEM')

	print "Registrando usuario con:\n\t*Nombre: {}\n\t*Email: {}\n\t*Alias: {}".format(nombre, email, alias)
	print "..."
	#Escritura de la peticion de registro
	url = 'https://vega.ii.uam.es:8080/api/users/register'
	headers = {'Authorization': "Bearer " + token}
	args = {'nombre': nombre, 'email': email,'alias': alias, 'publicKey': publicKey}
	
	# Envio de solicitud, se almacena respuesta en r
	r = requests.post(url, headers=headers, json=args)

	#Guardamos la clave privada en un fichero solo si la respuesta tiene un codigo 200
	if r.status_code == 200 :
		with open("clave_privada.dat", "wb") as key_file:
			key_file.write(privateKey)
		key_file.closed
		with open("clave_publica.dat", "wb") as pukey_file:
			pukey_file.write(publicKey)
		pukey_file.closed
		with open("register.dat", "w") as reg_file:
			reg_file.write(r.text)
		reg_file.closed

		print "OK\nEstos son sus credenciales:"
		print "\t*Nombre: {}".format(r.json()['nombre'])
		print "\t*ts: {}".format(r.json()['ts'])
	else :
		print "ERROR!!!\n No se ha podido completar el registro satisfactoriamente"

	return

#casi equivalente a buscar clave publica
#userID: nombre de usuario o email
def buscar_clave_publica(userID, token):

	#Escritura de la peticion de clave publica
	url = 'https://vega.ii.uam.es:8080/api/users/getPublicKey'
	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}

	r = requests.post(url, headers=headers, json=args)

	if r.status_code == 200:
		return r.json()['publicKey']
	else:
		print "ERROR. No se ha encontrado la clabe publica del usuario {}".format(userID)
		return None

#casi equivalente a buscar clave publica
#return, en formato json, los siguientes campos:
#	userID
#	nombre
#	email
#	publicKey
#	ts
#TODO: confirmar que json devuelve un diccionario(seria muy facil mapear en la respuesta eso)
def buscar_identidad(data_search, token):

	print "Buscando usuario {} en el servidor...".format(data_search)

	#Escritura de la peticion de clave publica
	url = 'https://vega.ii.uam.es:8080/api/users/search'
	headers = {'Authorization': "Bearer " + token}
	args = {'data_search': data_search}

	r = requests.post(url, headers=headers, json=args)

	if r.status_code == 200:
		print "OK"
		d =  r.json()
		#dkeys = d.keys()
		print "{} usuarios encontrados".format(len(d))
		count = 0
		for item in d:
			print "[{}] {}, {}, ID: {}".format(count+1, d[count]['nombre'], d[count]['email'], d[count]['userID'])
			count += 1
	else:
		#return ERROR
		print "No se han encontrado usuarios que concuerden con su busqueda"

	return

#borra una identidad syss esta ha sido creada por el propio usuario
def borrar_identidad(userID, token):

	print "Borrando usuario {} del servidor...".format(userID)

	url = 'https://vega.ii.uam.es:8080/api/users/delete'
	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}

	r = requests.post(url, headers=headers, json=args)

	if r.status_code == 200:
		print "OK"
		print "El usuario con ID {} ha sido eliminado satisfactoriamente".format(r.json()['userID'])
	else:
		print "ERROR. No se ha podido borrar el usuario"

	return	

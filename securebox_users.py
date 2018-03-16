from Crypto.PublicKey import RSA
import requests

# almacena un usuario, genera las claves y guarda su clave publica en el servidor
# y la privada de forma local.
def registro(nombre, email, token):

	#Generacion de claves para RSA
	privateKey = RSA.generate(2048)
	#Se usa PEM porque lo dice el enunciado.
	publicKey = privateKey.publicKey().exportKey('PEM')

	#Escritura de la peticion de registro
	url = 'https://vega.ii.uam.es:8080/api/users/register'
	headers = {'Authorization': "Bearer " + token}
	args = {'nombre': nombre, 'email': email, 'publicKey': publicKey}
	
	# Envio de solicitud, se almacena respuesta en r
	r = requests.post(url, headers=headers, json=args)

	#Guardamos la clave privada en un fichero solo si la respuesta tiene un codigo 200
	if r.status_code == 200 :
		with open("noEsLaClave.dat", "wb") as key_file:
			key_file.write(privateKey)
		key_file.closed
		with open("register.dat", "w") as reg_file:
			reg_file.write(r.json()[nombre])
			reg_file.write(r.json()[ts])
		reg_file.closed
		return OK
	else :
		return ERROR


#casi equivalente a buscar clave publica
#userID: nombre de usuario o email
def buscar_clave_publica(userID, token):

	#Escritura de la peticion de clave publica
	url = 'https://vega.ii.uam.es:8080/api/users/getPublicKey'
	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}

	r = requests.post(url, headers=headers, json=args)

	if r.status_code == 200:
		return r.json()[publicKey]
	else:
		return ERROR

#casi equivalente a buscar clave publica
#return, en formato json, los siguientes campos:
#	userID
#	nombre
#	email
#	publicKey
#	ts
#TODO: confirmar que json devuelve un diccionario(seria muy facil mapear en la respuesta eso)
def buscar_identidad(data_search, token):

	#Escritura de la peticion de clave publica
	url = 'https://vega.ii.uam.es:8080/api/users/search'
	headers = {'Authorization': "Bearer " + token}
	args = {'data_search': data_search}

	r = requests.post(url, headers=headers, json=args)

	if r.status_code == 200:
		return r.json()
	else:
		return ERROR

#borra una identidad syss esta ha sido creada por el propio usuario
def delete_identity(userID):
	url = 'https://vega.ii.uam.es:8080/api/users/delete'
	headers = {'Authorization': "Bearer " + token}
	args = {'userID': userID}

	r = requests.post(url, headers=headers, json=args)

	if r.status_code == 200:
		return r.json()[userID]
	else:
		return ERROR


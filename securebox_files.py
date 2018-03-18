import securebox_files
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

#Funcion que sube un fichero cifrado, devuelve el id y tamanio del fichero

def subir_fichero(fichero_cifrado, token):
	
	with open(fichero_cifrado, 'r') as f:
		# Escritura de la peticion de la subida
		url = 'https://vega.ii.uam.es:8080/api/files/upload'
		headers = {'Authorization': "Bearer " + token}

		# Envio de solicitud, se almacena respuesta en r
		r = requests.post(url, headers=headers, files={'ufile':f})

	if r.status_code == 200 :
		return r.json()
	elif r.status_code == 403:
		print "Fichero demasiado grande"
		return OK
	else:
		return ERROR


def cifrar_y_subir_fichero(fichero, ID_receptor, token):
	
	with open(fichero, 'r') as f_no_cifrado:
		mensaje_cifrado = encriptar_all(f_no_cifrado.read(), ID_receptor, token)
		with open("cifr-" + fichero, 'w') as f_cifrado:
			f_cifrado.write(mensaje_cifrado)
			subir_fichero(f_cifrado, token)

# Funcion que descarga un fichero del sistema, devolviendolo en binario

def descargar_fichero(id_fichero, token):

	# Escritura de la peticion de la descarga
	url = 'https://vega.ii.uam.es:8080/api/files/download'
	headers = {'Authorization': "Bearer " + token}
	args = {'file_id': id_fichero}
	
	# Envio de solicitud, se almacena respuesta en r
	r = requests.post(url, headers=headers, json=args)

	# Devolvemos el fichero en binario solo si la respuesta tiene un codigo 200
	if r.status_code == 200 :
		return r.text
	elif r.status_code == 401:
		print "El id del fichero no es correcto."
		return OK
	else:
		return ERROR


# Funcion que lista todos los ficheros pertenecientes a un usuario
#return, en formato json, los siguientes campos:
#	files_list
#	num_files

def listar_ficheros(token):

	# Escritura de la peticion de la lista de ficheros
	url = 'https://vega.ii.uam.es:8080/api/files/list'
	headers = {'Authorization': "Bearer " + token}

	r = requests.post(url, headers=headers)

	# Devolvemos la respuesta en formato json (la lista de ficheros y el numero)

	if r.status_code == 200:
		return r.json()
	else:
		return ERROR

# Funcion que borra un fichero, devuelve el id del fichero eliminado

def borrar_fichero(id_fichero, token):

	# Escritura de la peticion de el borrado del fichero
	url = 'https://vega.ii.uam.es:8080/api/files/delete'
	headers = {'Authorization': "Bearer " + token}
	args = {'file_id': id_fichero}

	r = requests.post(url, headers=headers, json=args)

	# Devolvemos la respuesta en formato json (la lista de ficheros y el numero)

	if r.status_code == 200:
		return r.json()[file_id]
	elif r.status_code == 401:
		print "El id del fichero no es correcto."
		return OK
	else:
		return ERROR


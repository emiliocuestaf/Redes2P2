import securebox_crypto as crypto
import requests
import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

#Funcion que sube un fichero cifrado, devuelve el id y tamanio del fichero


def subir_fichero(fichero, token):
	
	with open(fichero, "r") as f:
		
		# Escritura de la peticion de la subida
		url = 'https://vega.ii.uam.es:8080/api/files/upload'
		headers = {'Authorization': "Bearer " + token}

		# Envio de solicitud, se almacena respuesta en r
		r = requests.post(url, headers=headers, files={'ufile':f})

		if r.status_code == 200 :
			dic = r.json()
			file_id = dic['file_id']
			file_size = dic['file_size']
			return file_id
		elif r.status_code == 403:
			print "-> ERROR: Fichero demasiado grande"
			return None
		else:
			return None
	return


def cifrar_y_subir_fichero(fichero, ID_receptor, token):
	
	print "-> Cifrando y subiendo el fichero " + fichero + "..."	
	with open(fichero, "r") as f:
		mensaje = f.read()

	mensaje_encriptado = crypto.firmar_y_encriptar_mensaje(mensaje, ID_receptor, token)
	
	with open("encrypted_"+fichero, "w") as f:
		f.write(mensaje_encriptado)

	print "-> Subiendo fichero " + fichero	

	file_id = subir_fichero("encrypted_"+fichero, token) 
	if file_id == None:
		os.remove("encrypted_"+fichero)
		print "-> ERROR: EL fichero no se ha podido subir correctamente"
		return
	os.remove("encrypted_"+fichero)
	print "-> OK"
	print "Subida realizada satisfactoriamente, ID del fichero " + file_id
	return 

# Funcion que descarga un fichero del sistema, devolviendolo en binario

def descargar_fichero(id_fichero, ID_emisor, token):

	print "-> Descargando el fichero " + id_fichero + "..."

	# Escritura de la peticion de la descarga
	url = 'https://vega.ii.uam.es:8080/api/files/download'
	headers = {'Authorization': "Bearer " + token}
	args = {'file_id': id_fichero}
	
	# Envio de solicitud, se almacena respuesta en r
	r = requests.post(url, headers=headers, json=args)

	# Devolvemos el fichero en binario solo si la respuesta tiene un codigo 200
	if r.status_code == 200 :

		print "-> OK: Descarga correcta"

		mensaje_cifrado = r.text
		mensaje_descifrado = crypto.desencriptar_all(mensaje_cifrado, ID_emisor, token)

		with open(id_fichero+".dat", "w") as f:
			f.write(mensaje_descifrado)
		
		print "-> OK: El fichero se ha descargado correctamente en: " + id_fichero + ".dat" 
		return
	elif r.status_code == 401:
		print "-> ERROR: El id del fichero no es correcto."
		return OK
	else:
		return ERROR


# Funcion que lista todos los ficheros pertenecientes a un usuario
#return, en formato json, los siguientes campos:
#	files_list
#	num_files

def listar_ficheros(token):
	print "-> Listando ficheros..."
	# Escritura de la peticion de la lista de ficheros
	url = 'https://vega.ii.uam.es:8080/api/files/list'
	headers = {'Authorization': "Bearer " + token}

	r = requests.post(url, headers=headers)

	# Devolvemos la respuesta en formato json (la lista de ficheros y el numero)
	if r.status_code == 200:
		d =  r.json()
		print "-> {} ficheros encontrados:".format(d['num_files'])
		flist = d['files_list']
		count = 0
		for item in flist:
			print "-> [{}] ID: {}, fileName: {}".format(count+1, item['fileID'], item['fileName'])
			count += 1
		print "OK: Ficheros mostrados correctamente"
		return 
	else:
		print "ERROR: No se han podido mostrar todos los ficheros satisfactoriamente"
		return 

# Funcion que borra un fichero, devuelve el id del fichero eliminado

def borrar_fichero(id_fichero, token):
	print "-> Borrando el fichero con ID "+ id_fichero + "..."

	# Escritura de la peticion de el borrado del fichero
	url = 'https://vega.ii.uam.es:8080/api/files/delete'
	headers = {'Authorization': "Bearer " + token}
	args = {'file_id': id_fichero}

	r = requests.post(url, headers=headers, json=args)

	# Devolvemos la respuesta en formato json (la lista de ficheros y el numero)

	if r.status_code == 200:
		print "-> OK: El fichero " + r.json()['file_id'] + "ha sido borrado satisfactoriamente"
		return 
	elif r.status_code == 401:
		print "-> ERROR: El id del fichero no es correcto."
		return
	else:
		print "-> ERROR: El fichero no ha sido posible borrar el fichero correctamente"
		return 


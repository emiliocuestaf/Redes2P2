########
# REDES 2 - PRACTICA 2
# FICHERO: securebox_client.py
# DESCRIPCION: Fichero que define el comportamiento mas externo del cliente para securebox
# AUTORES: 
#	* Luis Carabe Fernandez-Pedraza 
#	* Emilio Cuesta Fernandez
# LAST-MODIFIED: 20-3-2018
########

import argparse
import sys
sys.path.insert(0, './src')
import ast
import securebox_files as files 
import securebox_crypto as crypto
import securebox_users as users

# Guardamos las direcciones que nos interesan 
conf_path = "./conf/authorization.dat"


#######
# FUNCION: read_dictionary()
# ARGS_IN: None
# DESCRIPCION: lee el fichero presente en conf_path (definido arriba) en un formato de diccionario
#				para tener la informacion mas accesible
# ARGS_OUT: devuelve un diccionario con los campos token y NIA
#######
def read_dictionary():
	d = {}

	# Abrimos el fichero de configuracion, controlando excepciones
	try:
		with open(conf_path) as f:
			# Guardamos todos los valores que haya en el fichero
		    for line in f:
		       (key, val) = line.split()
		       d[key] = val
	
	except EnvironmentError:
		print "-> ERROR: No se encontro el fichero de autenticacion"
		print "-> Dicho fichero debe corresponderse con la siguiente ruta: {}".format(conf_path)
		return None

	# Devolvemos el diccionario
	return d

#######
# FUNCION: main()
# ARGS_IN: None
# DESCRIPCION: funcion principal, encargada de parsear el mensaje que llegue por argumentos y llamar a las funciones correspondientes
#######

def main():

	# Guardamos todas las posibles opciones que pueden llegar por argumentos, con el numero de argumentos que esperan y su descripcion

	parser = argparse.ArgumentParser(description='Servidor de transferencia y codificacion de archivos interactivo.')

	# Gestion de usuarios e identidades
	parser.add_argument('--create_id', nargs=3, help='Registro de un usuario', metavar=('nombre', 'email', 'alias'))

	parser.add_argument('--search_id', nargs=1, help='Busqueda de un usuario', metavar=('cadena'))

	parser.add_argument('--delete_id', nargs=1,  help='Eliminacion de una identidad registrada', metavar=('id'))

	# Subida y descarga de ficheros
	parser.add_argument('--upload', nargs=1, help='Subida de un fichero al servidor', metavar=('fichero'))

	parser.add_argument('--source_id', nargs=1,  help='ID del emisor del fichero', metavar=('id'))

	parser.add_argument('--dest_id', nargs=1, help='ID del receptor del fichero', metavar=('id'))

	parser.add_argument('--list_files', action='store_true', help='Lista todos los ficheros pertenecientes al usuario')

	parser.add_argument('--download', nargs=1, help='Recupera un fichero del servidor', metavar=('id_fichero'))

	parser.add_argument('--delete_file', nargs=1, help='Elimina un fichero del servidor', metavar=('id_fichero'))

	# Cifrado y firma de ficheros local
	parser.add_argument('--encrypt', nargs=1, help='Cifra un fichero para otro usuario indicado con --dest_id. Src_id necesario', metavar=('fichero'))

	parser.add_argument('--sign', nargs=1, help='Firma un fichero', metavar=('fichero'))

	parser.add_argument('--enc_sign', nargs=1, help='Encripta y firma un fichero', metavar=('fichero'))


	# Parseamos los argumentos
	args = parser.parse_args()

	#Control para ver que solo se ha pasado el numero de comandos necesarios
	count = 0
	for item in vars(args).values():
		if(item != None and item!=False):
			count += 1

	# Creamos el diccionario de NIA y token
	d = read_dictionary()

	if d == None:
		return 

	# Guardamos el token

	if 'token' in d:
  		token = d['token']
	else:
  		print "-> ERROR: Su fichero de autenticacion no se adecua a los requerimentos del programa"
  		print "-> ERROR: El campo token es ESTRICTEMENTE NECESARIO"
  		return
	
	# Vamos comprobando los posibles argumentos que nos han podido pasar, comprobando en cada caso que la peticion esta bien formada

	if args.create_id:
		if count != 1:
			print  "ERROR: No es posible utilizar --create_id al mismo tiempo que otros parametros"
			
		else:
			users.registro(nombre= args.create_id[0], email= args.create_id[1], alias= args.create_id[2], token= token)
	elif args.search_id:
		if count != 1:
			print "ERROR:  No es posible utilizar --search_id al mismo tiempo que otros parametros"
			
		else:
			users.buscar_identidad(data_search= args.search_id[0], token= token)
	elif args.delete_id:
		if count != 1:
			print " ERROR: No es posible utilizar --delete_id al mismo tiempo que otros parametros"
			
		else:
			users.borrar_identidad(userID= args.delete_id[0], token= token)
	elif args.upload:
		if count != 2  or args.dest_id == None:
			print "Para ejecutar --upload es necesario indicar --dest_id."
			print "No es posible utilizar --upload al mismo tiempo que otros parametros distintos a los anteriores"
		else:
			files.cifrar_y_subir_fichero(fichero= args.upload[0], ID_receptor= args.dest_id[0], token= token)
		
	elif args.list_files:
		if count != 1:
			print "No es posible utilizar --list_files al mismo tiempo que otros parametros"
			 
		else:
			files.listar_ficheros(token= token)

	elif args.download:
		if count != 2 or args.source_id == None:
			print "Para ejecutar --download es necesario indicar --source_id."
			print "No es posible utilizar --download al mismo tiempo que otros parametros distintos a --source_id"
		else:
			files.descargar_fichero(id_fichero= args.download[0], ID_emisor= args.source_id[0], token= token)

	elif args.delete_file:
		if count != 1:
			print "No es posible utilizar --delete_file al mismo tiempo que otros parametros"
			
		else:
			files.borrar_fichero(id_fichero= args.delete_file[0],token= token)
	elif args.encrypt:
		if count != 2 or args.dest_id == None:
			print "Para ejecutar --encrypt es necesario indicar --dest_id."
			print "No es posible utilizar --encrypt al mismo tiempo que otros parametros distintos de --dest_id"
		else:
			crypto.encriptar_fichero(fichero= args.encrypt[0], ID_receptor= args.dest_id[0], token= token)
	
	elif args.sign:
		if count != 1:
			print "No es posible utilizar --sign al mismo tiempo que otros parametros"
			
		else:
			crypto.firmar_fichero(fichero= args.sign[0])
	elif args.enc_sign:
		if count != 2 or args.dest_id == None:
			print "Para ejecutar --encrypt es necesario indicar --dest_id."
			print "No es posible utilizar --enc_sign al mismo tiempo que otros parametros distintos de --dest_id"	
		else:
			crypto.firmar_y_encriptar(fichero= args.enc_sign[0], ID_receptor= args.dest_id[0], token= token)

	elif args.dest_id:
		if args.upload == None and args.encrypt == None and args.enc_sign == None:
			print "No tiene sentido utilizar --dest_id sin --upload, --encrypt o --enc_sign"
			
	elif args.source_id:
		if args.upload == None:
			print "No tiene sentido utilizar --source_id sin --download"

	else: 
		print "ERROR: Utilice los argumentos correctamente. Para saber mas, utilice el comando:\n\n\tpython securebox_client.py --help\n"

	return

# Hacemos que python interprete esta funcion como main y no como libreria
if __name__ == '__main__':
   main()

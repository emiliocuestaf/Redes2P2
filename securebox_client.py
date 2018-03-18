import argparse
import sys
import ast
import securebox_files as files 
import securebox_crypto as crypto
import securebox_users as users

#Codigo sacado online
def read_dictionary():
	d = {}
	with open("authorization.dat") as f:
	    for line in f:
	       (key, val) = line.split()
	       d[key] = val
	return d

def main():

	parser = argparse.ArgumentParser(description='Servidor de transferencia y codificacion de archivos interactivo.')

	# Gestion de usuarios e identidades
	#TODO: WORK WITHOUT ALIAS
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

	args = parser.parse_args()

	#Control para ver que solo se ha pasado el numero de comandos necesarios
	count = 0
	for item in vars(args).values():
		if(item != None and item!=False):
			count += 1

	#TODO: control de errores in here
	d = read_dictionary()	
	token = d['token']

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
			print "Para ejecutar --upload es necesario indicar --dest_id. \n No es posible utilizar --upload al mismo tiempo que otros parametros distintos a los anteriores"
			
		else:
			files.upload(cadena= args.upload[0], token= token)

	elif args.dest_id:
		if args.upload == None and args.encrypt == None:
			print "No tiene sentido utilizar --dest_id sin --upload o --encrypt"
			
	elif args.source_id:
		if args.upload == None:
			print "No tiene sentido utilizar --source_id sin --upload"
			
	elif args.list_files:
		if count != 1:
			print "No es posible utilizar --list_files al mismo tiempo que otros parametros"
			 
		else:
			print  "Subiendo fichero con nombre: "+  args.upload[0]
			files.list_files(cadena= args.create_id[0], token= token)

	elif args.download:
		if count != 1:
			return "No es posible utilizar --download al mismo tiempo que otros parametros"
			
		else:
			pass
			#llamada a funcion
	elif args.delete_file:
		if count != 1:
			return "No es posible utilizar --delete_file al mismo tiempo que otros parametros"
			
		else:
			pass
			#llamada a funcion
	elif args.encrypt:
		if count != 1:
			return "No es posible utilizar --encrypt al mismo tiempo que otros parametros"
			
		else:
			pass
			#llamada a funcion
	elif args.sign:
		if count != 1:
			return "No es posible utilizar --sign al mismo tiempo que otros parametros"
			
		else:
			pass
			#llamada a funcion
	elif args.enc_sign:
		if count != 1:
			return "No es posible utilizar --enc_sign al mismo tiempo que otros parametros"	
		else:
			pass
			#llamada a funcion
	else: 
		return "ERROR: Utilice los argumentos correctamente. Para saber mas, utilice el comando:\n\n\tpython securebox_client.py --help\n"

if __name__ == '__main__':
   main()
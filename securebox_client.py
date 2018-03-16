import argparse
import sys
import securebox_files
import securebox_crypto
import securebox_users


def main():
	parser = argparse.ArgumentParser(description='Servidor de transferencia y codificacion de archivos interactivo.')

	# Gestion de usuarios e identidades
	#TODO: WORK WITHOUT ALIASE
	parser.add_argument('--create_id', nargs=3, help='Registro de un usuario')

	parser.add_argument('--search_id', nargs=1, help='Busqueda de un usuario')

	parser.add_argument('--delete_id', nargs=1,  help='Eliminacion de una identidad registrada')

	# Subida y descarga de ficheros
	parser.add_argument('--upload', nargs=1, help='Subida de un fichero al servidor')

	parser.add_argument('--source_id', nargs=1,  help='ID del emisor del fichero')

	parser.add_argument('--dest_id', nargs=1, help='ID del receptor del fichero')

	parser.add_argument('--list_files', action='store_true', help='Lista todos los ficheros pertenecientes al usuario')

	parser.add_argument('--download_id', nargs=1, help='Recupera un fichero del servidor')

	parser.add_argument('--delete_file', nargs=1, help='Elimina un fichero del servidor')

	# Cifrado y firma de ficheros local
	parser.add_argument('--encrypt', nargs=1, help='Cifra un fichero para otro usuario indicado con --dest_id. Src_id necesario')

	parser.add_argument('--sign', nargs=1, help='Firma un fichero')

	parser.add_argument('--enc_sign', nargs=1, help='Encripta y firma un fichero')

	args = parser.parse_args()

	#Control para ver que solo se ha pasado el numero de comandos necesarios
	count = 0
	for item in vars(args).values():
		if(item != None):
			count += 1

	if args.create_id:
		if count != 1:
			print "No es posible utilizar --create_id al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
	elif args.search_id:
		if count != 1:
			print "No es posible utilizar --search_id al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
	elif args.delete_id:
		if count != 1:
			print "No es posible utilizar --delete_id al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
	elif args.upload:
		if count != 3 or args.source_id == None or args.dest_id == None:
			print "Para ejecutar --upload es necesario indicar --source_id y --dest_id."
			print "No es posible utilizar --upload al mismo tiempo que otros parametros distintos a los anteriores"
			return
		else:
			pass
			#llamada a funcion
	elif args.dest_id:
		if args.upload == None and args.encrypt == None:
			print "No tiene sentido utilizar --dest_id sin --upload o --encrypt"
			return
	elif args.source_id:
		if args.upload == None:
			print "No tiene sentido utilizar --source_id sin --upload"
			return
	elif args.list_files:
		if count != 1:
			print "No es posible utilizar --list_files al mismo tiempo que otros parametros"
			return 
		else:
			pass 
			#llamada a funcion
	elif args.download:
		if count != 1:
			print "No es posible utilizar --download al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
	elif args.delete_file:
		if count != 1:
			print "No es posible utilizar --delete_file al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
	elif args.encrypt:
		if count != 1:
			print "No es posible utilizar --encrypt al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
	elif args.sign:
		if count != 1:
			print "No es posible utilizar --sign al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
	elif args.enc_sign:
		if count != 1:
			print "No es posible utilizar --enc_sign al mismo tiempo que otros parametros"
			return
		else:
			pass
			#llamada a funcion
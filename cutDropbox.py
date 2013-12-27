#!/usr/bin/env python

from optparse import OptionParser
from dropbox import client, rest, session
import sys
import json
import tarfile
import os

APP_KEY = 'YOUR_APP_KEY'
APP_SECRET = 'YOUR_APP_SECRET'
ACCESS_TYPE = 'dropbox'

def save_token(token,archivo):
	fich = open(archivo,"w")
	fich.write("|".join([token.key, token.secret]))
	fich.close()

def load_token(archivo):
        try:
		fich = open(archivo,'r')
		token = fich.read()	
		fich.close()
            	return (token.split('|')[0],token.split('|')[1])
        except IOError:
            	print "[-] Error. No token file"
		exit(0)

def comprimeD(path,tarball):
	path_file = path+tarball.split('/')[len(tarball.split('/'))-1]
	tar = tarfile.open(path_file, "w:gz")
	tar.add(path)
	tar.close()
	print "[*] Compress in: %s"%path_file
	return path_file

def print_info(informacion):
	print "referral_link:	%s\nNombre:		%s\nuid:		%s\ncountry:	%s\nemail:		%s"%(informacion['referral_link'],informacion['display_name'],informacion['uid'],informacion['country'],informacion['email'])

def make_token(archivo,*argumentos):
	sess = session.DropboxSession(argumentos[0],argumentos[1],ACCESS_TYPE)	
	request_token = sess.obtain_request_token()
	url = sess.build_authorize_url(request_token)
	print "url:", url
	print "Please visit this website and press the 'Allow' button, then hit 'Enter' here."
	raw_input()
	access_token = sess.obtain_access_token(request_token)
	save_token(access_token,archivo)


def conecta(archivo,action,*argumentos):
	
	sess = session.DropboxSession(APP_KEY,APP_SECRET,ACCESS_TYPE)
	print "[*] Conected"

	try :
		sess.set_token(*load_token(archivo))
		print "[*] Token loaded: %s"%archivo
	except Exception,e:
		print "[-] Fail Loading token. Error: %s"%e
		exit(0)
	cliente = client.DropboxClient(sess)
	print "[*] Linked account: %s"%cliente.account_info()['email']
	
	if (action == 1):
		print_info(cliente.account_info())
	elif (action == 2):
		print "[*] Listing directory."
		try:
			folder_metadata = cliente.metadata(argumentos[0])
			for s in folder_metadata['contents']:
				sys.stdout.write("[+] ")
				for metadata in s:
					sys.stdout.write("%s "%s[metadata])
				sys.stdout.write("\n")
		except Exception,e:
			print "[-] Error: %s"%e
	elif (action == 3):
		path_file = comprimeD(argumentos[0],argumentos[1])
		f = open(path_file,"rb")
		response = cliente.put_file(argumentos[1],f)
		print "[+] Backup uploaded."
		print "	[*] Info remote file:\n	[*] path: %s\n	[*] size: %s (%s bytes)\n	[*] mtime: %s\n	[*] modified: %s"%(response['path'],response['size'],response['bytes'],response['client_mtime'],response['modified'])
		print "[*] Remove local file: %s"%path_file
		os.remove(path_file)
	elif (action == 4):
		response = cliente.file_delete(argumentos[0])
		print "[*] Deleted remote file: %s"%argumentos[0]
		print "	[*] Info remote file:\n	[*] path: %s\n	[*] size: %s (%s bytes)\n	[*] mtime: %s\n	[*] modified: %s"%(response['path'],response['size'],response['bytes'],response['client_mtime'],response['modified'])
	elif (action == 5):
		out = open(argumentos[1], 'wb')
		f, response = cliente.get_file_and_metadata(argumentos[0])
		out.write(f.read())
		out.close()
		print "[+] File downloaded."
		print "	[*] Info remote file:\n	[*] path: %s\n	[*] size: %s (%s bytes)\n	[*] mtime: %s\n	[*] modified: %s"%(response['path'],response['size'],response['bytes'],response['client_mtime'],response['modified'])
	elif (action == 6):
		f = open(argumentos[0],"rb")
		response = cliente.put_file(argumentos[1],f)
		f.close()
		print "[+] File uploaded."
		print "	[*] Info remote file:\n	[*] path: %s\n	[*] size: %s (%s bytes)\n	[*] mtime: %s\n	[*] modified: %s"%(response['path'],response['size'],response['bytes'],response['client_mtime'],response['modified'])

		
def opciones():
	parser = OptionParser("usage: %prog [options] \nExample: ./cutDropbox.py -t token_dropbox.txt -c -d /home/sink/files -o /Backups/files.tar.gz\nExample: ./cutDropbox.py --create-token token_dropbox.txt -k <app key> -s <secret key>\nExample: ./cutDropbox.py -t token_dropbox.txt -g /Backups/files.tar.gz -o /home/sink/files_dropbox.tar.gz\nExample: ./cutDropbox.py -t token_dropbox.txt -l /\nExample: ./cutDropbox.py -t token_dropbox.txt -r /Backups/files.tar.gz")
	parser.add_option("-i", "--info",
                  action="store_true", dest="info", help="Get account info")
	parser.add_option("-c","--compress",
                  action="store_true", dest="compress", help="Compress directory.")
	parser.add_option("-t", "--token",
                  action="store", type="string", dest="token", help="Token for connect.")
	parser.add_option("--create-token",
                  action="store", type="string", dest="file_dest", help="Create a token.")
	parser.add_option("-k","--app-key",
                  action="store", type="string", dest="app_key", help="App key.")
	parser.add_option("-s","--secret-key",
                  action="store", type="string", dest="secret_key", help="Secret key.")
	parser.add_option("-l", "--ls",
                  action="store", type="string", dest="directory", help="Listing the folder")
	parser.add_option("-d", "--directory",
                  action="store", type="string", dest="path", help="local directory/file to copy")
	parser.add_option("-g", "--get",
                  action="store", type="string", dest="file", help="Download remote file.")
	parser.add_option("-o", "--output",
                  action="store", type="string", dest="output", help="Output directory/file where save the backup.")
	parser.add_option("-r", "--remove",
                  action="store", type="string", dest="remove", help="Remove remote file/directory.")

	(options, args) = parser.parse_args()


	if (len(sys.argv) == 1):
		parser.print_help()
	elif (options.token != None):
		if (options.info):	
			conecta(options.token,1,None)
		elif (options.directory != None):
			conecta(options.token,2,options.directory)
		elif (options.path != None) and (options.output != None) and (options.compress):
			conecta(options.token,3,options.path,options.output)
		elif (options.path != None) and (options.output != None) and (not options.compress):
			conecta(options.token,6,options.path,options.output)
		elif (options.remove != None):
			conecta(options.token,4,options.remove)
		elif (options.file != None) and (options.output != None):
			conecta(options.token,5,options.file,options.output)
	elif (options.file_dest != None) and (options.secret_key != None) and (options.app_key != None):
		make_token(options.file_dest,options.app_key,options.secret_key)
	else:
		print "[-] Error: Need a token."

if __name__ == '__main__':
    opciones()

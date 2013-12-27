cupDropbox
==========

It is a little tool to upload, download and list directories. It is very useful to compress directories and upload automatically.

Documentation and installation
------------------------------

#### Documentation about Dropbox API.
```
 https://www.dropbox.com/static/developers/dropbox-python-sdk-1.5.1-docs/index.html 
```
#### Download and installation
```
https://www.dropbox.com/developers/core/sdk 
```
### Installation
```
 unzip dropbox-python-sdk-1.5.1.zip
 cd dropbox-python-sdk-1.5.1
 python setup.py install 
```

Usage
-----

```
[sink@Hardcore ~/Scripts]$ ./cutDropbox.py -h
Usage: cutDropbox.py [options]
Example: ./cutDropbox.py -t token_dropbox.txt -c -d /home/sink/files -o /Backups/files.tar.gz
Example: ./cutDropbox.py --create-token=token_dropbox.txt -k <app key> -s <secret key>
Example: ./cutDropbox.py -t token_dropbox.txt -g /Backups/files.tar.gz -o /home/sink/files_dropbox.tar.gz
Example: ./cutDropbox.py -t token_dropbox.txt -l /
Example: ./cutDropbox.py -t token_dropbox.txt -r /Backups/files.tar.gz

Options:
  -h, --help            show this help message and exit
  -i, --info            Get account info
  -c, --compress        Compress directory.
  -t TOKEN, --token=TOKEN
                        Token for connect.
  --create-token=FILE_DEST
                        Create a token.
  -k APP_KEY, --app-key=APP_KEY
                        App key.
  -s SECRET_KEY, --secret-key=SECRET_KEY
                        Secret key.
  -l DIRECTORY, --ls=DIRECTORY
                        Listing the folder
  -d PATH, --directory=PATH
                        local Directory/file to copy
  -g FILE, --get=FILE   Download remote file.
  -o OUTPUT, --output=OUTPUT
			Output directory/file where save the backup.
  -r REMOVE, --remove=REMOVE
                        Remove remote file/directory.
```


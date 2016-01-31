#!/usr/bin/env bash
#  Script: ocdec.sh
#  Author: Andrey Arapov
#  Email: andrey.arapov@nixaid.com
#
#  Copyright (C) 2015 Andrey Arapov
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#
# Version:
#  1.0.1 - little usage fix (22 Sep 2015)
#  1.0.0 - Initial release (22 Sep 2015)
#
# Tested with:
#  - ownCloud 8.1.3
#
# Limitations:
#  - it is really really slow (the largest bottleneck is in awk part of the script)
#
#
# === Usage notes
#
# Current directory should be the ownCloud data directory !
# You can find it this way:
# grep -i datadirectory /srv/pathto/owncloud/config/config.php
#  'datadirectory' => '/srv/ownclouddata/',
#
# Make sure you have exported env. variable, e.g.
# export userLoginPass='s3cr3tpass'
#
#
# === Usage Example - Decrypt just 1 file
#
# export userLoginPass='s3cr3tpass'
# cd /srv/ownclouddata
# /tmp/ocdec.sh testuser1/files/secretfile.txt
#
#
# === Usage Example 2 - Decrypt Everything!
#
# 1. Create directory structure for decrypted data
#
# export USER=testuser1
# export userLoginPass='s3cr3tpass'
# cd /srv/ownclouddata
# find ${USER}/files -type d -print0 |xargs -0 -I@ echo "@" |cut -sd / -f 2- |xargs -I@ mkdir -p "${USER}-DECRYPTED/@"
#
#
# 2. Decrypt the data
#
# cd /srv/ownclouddata
# find ${USER}/files -type f -print0 |xargs -0 -I@ sh -c '/tmp/ocdec.sh "@" > "${USER}-DECRYPTED/$(echo "@"|cut -sd / -f 2-)"'
#
# Now all your data is decrypted & available at the ${USER}-DECRYPTED/ path !
#
#


# Beginning of a script

#
# Get User Private Key
#
# arg1: username
# arg2: password
function decryptUserPrivateKey() {
  USER=$1
  userLoginPass=$2
  userPrivKeyPath="$USER/files_encryption/OC_DEFAULT_MODULE/$USER.privateKey"
  if [ ! -r "$userPrivKeyPath" ]; then
    echo "decryptUserPrivateKey():: File "$userPrivKeyPath" does not exist or not enough permissions! Aborting."
    return 1
  fi

  encPrivKeyContentsALL="$(cat "$userPrivKeyPath")"
  # Some non-GNU versions of sed do not support pattern matches. In that case use: perl -pne 's/(00iv00.*)?00iv00.*/$1 /'
  encPrivKeyContentsBASE64="$( sed -r 's/^HBEGIN:.+:HEND-*//;s/(00iv00.*)?00iv00.*{16}xx/\1/' <(echo "${encPrivKeyContentsALL}") )"
  plainPrivKeyIV="$( sed -r 's/^HBEGIN.*00iv00//;s/xx$//' <(echo "${encPrivKeyContentsALL}") )"
  userLoginPassHEX=$(echo -n $userLoginPass |od -An -tx1 |tr -dc '[:xdigit:]')
  plainPrivKeyIVHEX=$(echo -n $plainPrivKeyIV |od -An -tx1 |tr -dc '[:xdigit:]')

  echo "$( openssl enc -AES-256-CFB -d -nosalt -base64 -A -K $userLoginPassHEX -iv $plainPrivKeyIVHEX -in <(echo $encPrivKeyContentsBASE64) )"
}

#
# Decrypt the file
#
# arg1: username
# arg2: path to an encrypted file (e.g. 'files/secretfile.txt' or 'files/Photos/Squirrel.jpg')
# arg3: user Private Key in plaintext
function decryptFile() {
  USER="$1"
  encFilePath="$2"
  plainUserPrivKey="$3"

  if [ ! -r "${USER}/$encFilePath" ]; then
    echo "decryptFile():: File "${USER}/$encFilePath" does not exist or not enough permissions! Aborting."
    return 1
  fi
  if ! grep -q "^HBEGIN:" "${USER}/$encFilePath"; then
    echo "decryptFile():: File "${USER}/$encFilePath" does not seem to be encrypted! Aborting."
    return 1
  fi

  # --- Get the FileKey ---
  userFileShareKeyPath="${USER}/files_encryption/keys/${encFilePath}/OC_DEFAULT_MODULE/${USER}.shareKey"
  encFileKeyPath="${USER}/files_encryption/keys/${encFilePath}/OC_DEFAULT_MODULE/fileKey"

  decUserFileShareKeyHEX="$( openssl rsautl -decrypt -inkey <(echo "$plainUserPrivKey") -in "$userFileShareKeyPath" |od -An -tx1 |tr -dc '[:xdigit:]' )"
  if [ -z "$decUserFileShareKeyHEX" ];then echo "decryptFile():: The User Private Key is not good. Are you sure your ownCloud User Login password is correct?"; return 1; fi

  decFileKeyContent="$( openssl rc4 -d -in "$encFileKeyPath" -iv 0 -K $decUserFileShareKeyHEX )"
  decFileKeyContentHEX="$( echo -n $decFileKeyContent |od -An -tx1 |tr -dc '[:xdigit:]' )"
  decFileKeyContentHEX=${decFileKeyContentHEX:0:64}
  # --- Get the FileKey ---

  # --- Decrypt the file ---
  # OC writes the encrypted file in 8K chunks, each containing it's own iv in the end
  chunkSize=8192
  while read -d '' -n $chunkSize CHUNK || [ -n "$CHUNK" ]; do
    #split chunk into payload an iv string (strip padding from iv)          
    read payload iv <<<`echo $CHUNK | sed -r 's/(.*)00iv00(.{16})xx/\1 \2/'`
    # convert base64 iv into hex
    iv=$(echo -n "$iv" | od -An -tx1 | tr -dc '[:xdigit:]' )
    # decode chunk
    openssl enc -AES-256-CFB -d -nosalt -base64 -A -K $decFileKeyContentHEX -iv $iv -in <(echo "$payload")
    done <<<`sed -r 's/^HBEGIN:.+:HEND-*//' <"${USER}/$encFilePath"` # pipe the encrypted file without head into the loop
  # --- Decrypt the file ---
}

# Get a username from the path (arg1)
USER="$(echo $1 |cut -sd / -f 1)"

# Strip off the username from the path (arg1)
FILETD="$(echo $1 |cut -sd / -f 2-)"

if [ ! -r "$USER" ]; then
  echo "User directory cannot be found! Are you sure you are in ownCloud's data directory?"
  exit 1
fi

if [ -z "$userLoginPass" ]; then
  echo "Please set userLoginPass environment variable!"
  exit 1
fi

if [ ! -r "$1" ]; then
  echo "File specified $1 does not exist or not enough permissions to access it!"
  exit 1
fi

#
# TODO: Add checks for available tools installed: openssl, sed, cat, od, tr, mawk
#

#
# 1) Locate and decrypt User Private Key
#
# TODO: to decrypt User Private Key only once when running this script in a loop (decrypting multiple files)
plainUserPrivKey="$(decryptUserPrivateKey $USER $userLoginPass)";

#
# 2) Decrypt the shareKey, then the fileKey, then the file and output the plaintext
#
decryptFile $USER "$FILETD" "$plainUserPrivKey"

# End of a script

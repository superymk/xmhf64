#!/bin/bash

set -xe
if [ $# -le 0 ]; then
	echo "Error: no enough arguments"; exit 1
fi

DOWNLOAD_DIR="$1"
mkdir -p "$DOWNLOAD_DIR"
shift

download () {
	TARGET_FILE="$DOWNLOAD_DIR/$2"
	if [ -f "$TARGET_FILE" ]; then
		echo "$TARGET_FILE already exists"
	else
		if ! python3 -c 'import gdown'; then
			python3 -m pip install gdown
		fi
		URL="https://drive.google.com/uc?id=${1}&confirm=t"
		python3 -m gdown "$URL" -O "$TARGET_FILE"
	fi
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		debian11x86.qcow2)
			download "1I0Ps8uZFYskv5dg04esXok7DR1k6ox1L" "$1"
			;;
		debian11x64.qcow2)
			download "1IRXzOqpDbNtkojnUN-jSjS4F9GCA3G_l" "$1"
			;;
        debian11efi.qcow2)
            download "1IWZfDbkurCmRaSMkTCum40LzWgm7ym-n" "$1"
			;;
		*)
			echo "Error: unknown file $1"; exit 1
			;;
	esac
	shift 
done


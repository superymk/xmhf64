#!/bin/bash

# Specify the path where the files should be checked or downloaded
target_directory="."

# Function to download a file if it does not exist
download_if_missing() {
    local filename="$1"
    local download_url="$2"
    local file_path="$target_directory/$filename"

    # Check if the file exists
    if [ ! -f "$file_path" ]; then
        echo "File $filename does not exist. Downloading..."
        # Create target directory if it does not exist
        mkdir -p "$target_directory"
        # Download the file
        python3 -m gdown "$download_url" -O "$file_path"
        echo "Download completed."
    else
        echo "File $filename already exists. No action taken."
    fi
}

# URLs for downloading files (example URLs, replace with actual URLs)
url_debian11efi="https://drive.google.com/uc?id=1IWZfDbkurCmRaSMkTCum40LzWgm7ym-n&confirm=t"
url_debian11x64="https://drive.google.com/uc?id=1IRXzOqpDbNtkojnUN-jSjS4F9GCA3G_l&confirm=t"

# File names to check and download if missing
file_debian11efi="debian11efi.qcow2"
file_another="debian11x64.qcow2"

# Call the function for each file
download_if_missing "$file_debian11efi" "$url_debian11efi"
download_if_missing "$file_another" "$url_debian11x64"

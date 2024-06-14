#!/bin/bash

# Directories to compare
dir1="./received"
dir2="./files"

# Ensure both directories exist
if [ ! -d "$dir1" ] || [ ! -d "$dir2" ]; then
  echo "One or both directories do not exist."
  exit 1
fi

# Loop through files in the first directory
for file in "$dir1"/*; do
  # Extract filename
  filename=$(basename "$file")

  # Check if the file exists in the second directory
  if [ -f "$dir2/$filename" ]; then
    # Calculate SHA-256 hashes for both files
    hash1=$(sha256sum "$file" | awk '{print $1}')
    hash2=$(sha256sum "$dir2/$filename" | awk '{print $1}')

    # Compare hashes
    if [ "$hash1" == "$hash2" ]; then
      echo "Files $file and $dir2/$filename are identical."
    else
      echo "Files $file and $dir2/$filename differ."
      # Optionally perform diff to show differences
      echo "Differences:"
      diff "$file" "$dir2/$filename"
    fi
  else
    echo "No matching file for $filename in $dir2"
  fi
done

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
    # Compare the files
    echo "Comparing $file with $dir2/$filename"
    diff "$file" "$dir2/$filename"
  else
    echo "No matching file for $filename in $dir2"
  fi
done

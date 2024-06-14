#!/bin/bash

# Define the command
CMD="python3 ./test.py --file ./files/8192.txt --output 1"

# Execute the commands simultaneously and redirect outputs
$CMD > output1.txt 2> error1.txt &
$CMD > output2.txt 2> error2.txt &

# Wait for all background processes to finish
wait
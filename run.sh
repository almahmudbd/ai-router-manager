#!/bin/bash

# Change directory to where this script is located
cd "$(dirname "$0")"

# Run the Python script
python manager_v3.py

# Wait for user input (optional)
read -n 1 -s -r -p "Press any key to continue..."
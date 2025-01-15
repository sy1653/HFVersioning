# HFVersioning
HF Versioning is designed to automate build fingerprint changes.

Script expects two arguments input_string which is nothing but the repo init for the branch where you want to make the changes, build_string is the build fingerprint which you want to retain. Both can be updated in params.json and submit as input to the script.

How to run:
python auto_hf_versioning.py params.json

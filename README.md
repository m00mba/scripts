# beyondtrust_scanner.py
Checking to see if you maybe vulerable to cve-2026-1731
This python script scans for the beyondtrust version and looks at the binary of the build.

You may also use the -diff switch to compare 2 different targets.

samples
python3 beyondtrust_scanner.py target_hostname
python3 beyondtrust_scanner.py -diff target1_hostname target2_hostname
Scan multiple nodes python3 beyondtrust_scanner.py $(cat targets.txt)

# beyondtrust_scanner.py
Checking to see if you maybe vulerable to cve-2026-1731
This python script scans for the beyondtrust version and looks at the binary of the build.

You may also use the -diff switch to compare 2 different targets.

samples
python3 beyondtrust_scanner.py target_hostname
python3 beyondtrust_scanner.py -diff target1_hostname target2_hostname
Scan multiple nodes python3 beyondtrust_scanner.py $(cat targets.txt)

Why the Diff is your strongest tool
When you use -diff, the script aligns the MD5 Hash of the Master and the Traffic node. Since the Traffic node is showing a "Heartbeat" (today's date) and the Master is showing "2024-12-21," the app team might argue they are different.

The -diff output visually shows that while the Build Date field is different, the MD5 Hash is a 100% match. This proves the "Heartbeat" is just a timestamp and the underlying software is the same unpatched version.

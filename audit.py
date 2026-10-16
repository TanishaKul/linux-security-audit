import os
import stat
import subprocess

findings = []

def check_shadow_permissions():
	permissions = stat.filemode(os.stat("/etc/shadow").st_mode)
	if permissions [-3:]=="---":
		print("[PASS] /etc/shadow permission are secure")
	else:
		finding = "[HIGH] /etc/shadow has insecure permissions"
		print(finding)
		findings.append(finding)

def check_empty_passwords():
	with open("/etc/shadow","r") as file:
		for line in file:
			parts= line.strip().split(":")
			username=parts[0]
			password_field=parts[1]
			if password_field==" ":
				finding = f"[HIGH] Empty password found for user:{username}"
				print (finding)
				findings.append(finding)

def check_listening_ports():
	result =subprocess.run(["ss","-tuln"],capture_output=True,text=True)
	print("\n[INFO] Listening network ports:")
	for line in result.stdout.splitlines():
		if "Local Address:Port" not in line and line.strip():
			print(line)

def check_firewall():
	result = subprocess.run(["iptables","L"],capture_output=True,text=True)
	if "policy ACCEPT" in result.stdout:
		finding="[MEDIUM]  Firewall filtering may not be configured"
		print(finding)
		findings.append(finding)
	else:
		print("[INFO] iptables output does not show ACCEPT poicy")

def check_world_writable():
	result =subprocess.run(["find","/","-xdev","-type","f","-perm","-0002"],capture_output=True,text=True)
	if result.stdout.strip():
		for file in result.stdout.splitlines():
			finding = f"[HIGH] World-writable file found: {file}"
			print(finding)
			findings.append(finding)
	else:
		print("[PASS] No world-writable files found")

def check_outdated_packages():
	result = subprocess.run(["apt","list","--upgradable"],capture_output=True,text=True)
	lines = result.stdout.splitlines()
	if len(lines)>1:
		print(f"[INFO] {len(lines)-1} packages have updates available")
	else:
		print("[PASS] No outdated packages found")

check_shadow_permissions()
check_empty_passwords()
check_listening_ports()
check_firewall()
check_world_writable()
check_outdated_packages()

print("\n============AUDIT SUMMARY=============")
if findings:
	for finding in findings:
		print(finding)
else:
	print("No security findings detected.")
print("========================================")

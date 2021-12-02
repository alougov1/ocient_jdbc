#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import subprocess
import os
import shutil
import urllib.request

in_docker = os.environ.get('IN_XGJDBC_DOCKER_CONTAINER', False)
if not in_docker:
    input("You are not running in a docker container. This probably will do weird things and not work, use at your own risk. Enter anything to contine: ")

# Download the secrets
urllib.request.urlretrieve("http://cos/webdav/misc/xgjdbc_deploy_keys/codesignstore.jks", "codesignstore.jks")
urllib.request.urlretrieve("http://cos/webdav/misc/xgjdbc_deploy_keys/codesignstore.pwd", "codesignstore.pwd")
urllib.request.urlretrieve("http://cos/webdav/misc/xgjdbc_deploy_keys/deploy_settings.xml", "deploy_settings.xml")
urllib.request.urlretrieve("http://cos/webdav/misc/xgjdbc_deploy_keys/private.key", "private.key")
urllib.request.urlretrieve("http://cos/webdav/misc/xgjdbc_deploy_keys/ssh.pwd", "ssh.pwd")

MAVEN_GLOBAL_SETTINGS = f"""
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
    <localRepository>{os.getcwd()}/.m2/repository</localRepository>
</settings>
"""

with open('mavenGlobalSettings.xml', 'w') as f:
    f.write(MAVEN_GLOBAL_SETTINGS)

ssh_pwd = ""
with open("ssh.pwd", 'r') as f:
    ssh_pwd = f.read()

tree = ET.parse("pom.xml")
version_elt = tree.getroot().find("{http://maven.apache.org/POM/4.0.0}version")

if version_elt == None:
    print("Could not find version in pom.xml")
    exit(1)

JDBC_VERSION = version_elt.text
print(f"Deploying version: {JDBC_VERSION}")
JAR_FILE = f"target/ocient-jdbc4-{JDBC_VERSION}-jar-with-dependencies.jar"

# Add the gpg key
proc = subprocess.run("gpg --pinentry-mode loopback --passphrase xeograph --import private.key", shell=True)
if proc.returncode != 2:
    print("Failed to add gpg key")

# Build and don't deploy so we can copy the jar to ocient archive
subprocess.run(f"mvn verify -gs mavenGlobalSettings.xml -s deploy_settings.xml -Djarsigner.storepass=$(cat codesignstore.pwd)", shell=True, check=True)

JAR_DIR = f"v{JDBC_VERSION}"
# Makes it easier to test, this file should never actually be here
try:
    shutil.rmtree(JAR_DIR)
except FileNotFoundError:
    pass
os.mkdir(JAR_DIR)
shutil.copy(JAR_FILE, JAR_DIR)
subprocess.call(f'chmod -R 777 {JAR_DIR}', shell=True)

# Copy jar to ocient archive
subprocess.run(f'sshpass -p "{ssh_pwd}" scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {JAR_DIR} user@ocient-archive:/home/user/www/ocientrepo/java/jdbc/', shell=True, check=True)

# Try to deploy jdbc to maven
subprocess.run(f"mvn deploy -gs mavenGlobalSettings.xml -s deploy_settings.xml -Djarsigner.storepass=$(cat codesignstore.pwd)", shell=True, check=True)

# Copy over userdocs to ocient archive
subprocess.run(f'sshpass -p "{ssh_pwd}" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null target/generated-docs/release_notes.html target/generated-docs/release_notes.pdf user@ocient-archive:/home/user/www/ocientrepo/java/jdbc/release_notes', shell=True, check=True)

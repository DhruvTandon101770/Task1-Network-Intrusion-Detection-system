Network Intrusion Detection System using Snort
Introduction:
This guide provides instructions for setting up and running a basic Network Intrusion Detection System (NIDS) using Snort on a Linux system. It covers installation, configuration, and basic usage.
Prerequisites:
Before beginning, ensure you have:

A Linux system (Ubuntu or Debian-based)
Root or sudo access
A network interface (this guide uses 'enp0s3' and 'enp3s0' - replace with your actual interface name)

Installation:

Install Snort by running:
sudo apt-get install snort
Set your network interface to promiscuous mode:
sudo ip link set enp0s3 promisc on
(Replace 'enp0s3' with your actual network interface name)

Configuration:

Edit the Snort configuration file:
sudo nano /etc/snort/snort.conf
Review and adjust settings as needed for your environment.
Test the Snort configuration:
sudo snort -T -i enp3s0 -c /etc/snort/snort.conf
(Replace 'enp3s0' with your actual network interface name)
Edit the local rules file:
sudo nano /etc/snort/rules/local.rules
Add the following rules to local.rules:
alert icmp any any -> $HOME_NET any (msg:"Ping Detected"; sid:100001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"SSH Authentication Attempt"; sid:100002; rev:1;)

Running Snort:
Start Snort in IDS mode with this command:
sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf
(Replace 'enp0s3' with your actual network interface name)
Understanding the Commands:

sudo apt-get install snort: Installs Snort
sudo ip link set enp0s3 promisc on: Sets the network interface to promiscuous mode
sudo nano /etc/snort/snort.conf: Opens the Snort configuration file for editing
sudo snort -T -i enp3s0 -c /etc/snort/snort.conf: Tests the Snort configuration
sudo nano /etc/snort/rules/local.rules: Opens the local rules file for editing
sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf: Runs Snort in IDS mode

Important Notes:

Ensure you replace 'enp0s3' and 'enp3s0' with your actual network interface names.
The provided rules are basic examples. You should develop more comprehensive rules for your specific security needs.
Regular updates to Snort and its rules are crucial for effective intrusion detection.

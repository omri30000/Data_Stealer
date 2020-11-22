# Data_Stealer
This project is a data stealer - it pretends to be an antivirus program that a user installs using an msi.
the code works differently with respect to it's location on the host machine.
when being ran for the first time, the virus installs and activates itself in as a hidden file in a hidden directory.

# Data Collection
The virus collects the following data and writes it into a log file:
* keystrokes
* screenshots
* IP addresses related to the host machine
* operating system's details
* running rroccess
* windows user's username
* user's Groups

# Investigation Tools Blocking
The virus will close the processes of the following programs once per minute:
* wireshark
* fiddler
* task manager

# Autorun
The virus will run itself automatically when the machine starts

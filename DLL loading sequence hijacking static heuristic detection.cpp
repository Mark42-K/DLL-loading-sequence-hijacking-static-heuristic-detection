#include<windows.h>
#include<wintrust.h>
#include<Softpub.h>
#include<iostream>


using std::cout;
using std::cin;
using std::endl;
using std::hex;
using std::string;

long Tread_Number = 0;
long SameAddrInterval = 0;
long SameExportAddr = 0;
long SameExportName = 0;
long SuspectedMalicious_DLL = 0;

void Sort(PDWORD* Array, DWORD NumberOfMember);


//Convert a visual address to a file offset address
DWORD RVA_To_FOA(PIMAGE_NT_HEADERS PImage_NT_Header, DWORD Vitual_Address);


//Get export structure
void Get_Export_Structure(char* Image_Address,
						  PIMAGE_NT_HEADERS PImage_NT_Header,
						  PIMAGE_EXPORT_DIRECTORY* PImage_Export_Directory,
						  char** DLL_Name,
						  PDWORD* AddressOfName,
						  PWORD* AddressOfNameOrdinals,
						  PDWORD* AddressOfFunction);


//Verify Digital Signature
bool Verify_Digital_Signature(string File_Path);


//Detect
int DLLHijack_Detection(char* Image_Address, PIMAGE_NT_HEADERS PImage_NT_Header);


//Decision criterion 1
bool Same_Export_Addr(PDWORD AddressOfFunction_Duplicate,int NumberOfFunctions, char* DLL_Name);


//Decision criterion 2
bool Same_Addr_Interval(PDWORD AddressOfFunction_Duplicate,int NumberOfFunctions);


//Decision criterion 3
bool Same_Export_Name(char* Image_Address, PIMAGE_NT_HEADERS PImage_NT_Header, PDWORD AddressOfName, int NumberOfNames);


//------------------------------------º¯Êý¶¨Òå----------------------------------------------
void Sort(PDWORD* Array,DWORD NumberOfMember)
{
	int i, j;
	DWORD temp;
	for (i = 0; i < NumberOfMember; i++)
	{
		DWORD temp_member = (*Array)[i];
		int temp_index = i;
		for (j = i + 1; j < NumberOfMember; j++)
		{
			if ((*Array)[j] < temp_member)
			{
				temp_member = (*Array)[j];
				temp_index = j;
			}
		}
		if (temp_index != i)
		{
			temp = (*Array)[temp_index];
			(*Array)[temp_index] = (*Array)[i];
			(*Array)[i] = temp;
		}
	}
}


DWORD RVA_To_FOA(PIMAGE_NT_HEADERS PImage_NT_Header, 
				 DWORD Vitual_Address)
{
	//File offset address
	DWORD FOA = 0;

	int number = 0;

	int Number_Of_Section = PImage_NT_Header->FileHeader.NumberOfSections;

	int Image_Section_Header_Size = sizeof(IMAGE_SECTION_HEADER);

	PIMAGE_SECTION_HEADER PImage_Section_Header = (PIMAGE_SECTION_HEADER)((DWORD)PImage_NT_Header + sizeof(IMAGE_NT_HEADERS));
	
	//Convert a visual address to a file offset address
	for (number; number < Image_Section_Header_Size; number++)
	{
		PIMAGE_SECTION_HEADER P = (PIMAGE_SECTION_HEADER)((DWORD)PImage_Section_Header + Image_Section_Header_Size * number);
		if ((P->VirtualAddress <= Vitual_Address) && (P->VirtualAddress + P->Misc.VirtualSize >= Vitual_Address))
		{
			FOA = Vitual_Address - (P->VirtualAddress - P->PointerToRawData);
			break;
		}
	}
	
	//Detemine whether the visual address if out of range
	if (number >= Image_Section_Header_Size)
	{
		cout << "Invailed Vitual Address!!" << endl;
		exit(1);
	}

	return FOA;
}


void Get_Export_Structure(char* Image_Address,
						  PIMAGE_NT_HEADERS PImage_NT_Header,
						  PIMAGE_EXPORT_DIRECTORY* PImage_Export_Directory,
						  char** DLL_Name,
						  PDWORD* AddressOfName,
						  PWORD* AddressOfNameOrdinals,
						  PDWORD* AddressOfFunction)
{
	//Gets the file offset address of the exported table
	DWORD FOA_Export_Directory = RVA_To_FOA(PImage_NT_Header, PImage_NT_Header->OptionalHeader.DataDirectory[0].VirtualAddress);

	//Location Export table
	*PImage_Export_Directory = (PIMAGE_EXPORT_DIRECTORY)(Image_Address + FOA_Export_Directory);

	*DLL_Name = (char*)(Image_Address + RVA_To_FOA(PImage_NT_Header, (*PImage_Export_Directory)->Name));

	//Gets an array of Pointers to the export function name from the export table structure
	if ((*PImage_Export_Directory)->AddressOfNames != 0)
	{
		*AddressOfName = (PDWORD)((DWORD)Image_Address + RVA_To_FOA(PImage_NT_Header, (*PImage_Export_Directory)->AddressOfNames));
	}

	//Gets an array of export function sequence Numbers from the export table structure
	if ((*PImage_Export_Directory)->AddressOfNameOrdinals != 0)
	{
		*AddressOfNameOrdinals = (PWORD)((DWORD)Image_Address + RVA_To_FOA(PImage_NT_Header, (*PImage_Export_Directory)->AddressOfNameOrdinals));
	}

	//Get an array of export function address from the export table structure
	if ((*PImage_Export_Directory)->AddressOfFunctions != 0)
	{
		*AddressOfFunction = (PDWORD)((DWORD)Image_Address + RVA_To_FOA(PImage_NT_Header, (*PImage_Export_Directory)->AddressOfFunctions));
	}

}


bool Verify_Digital_Signature(string File_Path)
{
	//Initialize WINTRUST_FILE_INFO structure
	WINTRUST_FILE_INFO File_Info;
	ZeroMemory(&File_Info, sizeof(WINTRUST_FILE_INFO));
	File_Info.cbStruct = sizeof(WINTRUST_FILE_INFO);
	File_Info.pcwszFilePath = (LPCWSTR)File_Path.c_str();
	File_Info.hFile = NULL;
	File_Info.pgKnownSubject = NULL;

	//Initialize WINTRUST_DATA Structure
	WINTRUST_DATA Trust_Data;
	ZeroMemory(&Trust_Data, sizeof(WINTRUST_DATA));
	Trust_Data.cbStruct = sizeof(WINTRUST_DATA);
	Trust_Data.pPolicyCallbackData = NULL;
	Trust_Data.pSIPClientData = NULL;
	Trust_Data.dwUIChoice = WTD_UI_NONE;
	Trust_Data.pFile = &File_Info;
	Trust_Data.fdwRevocationChecks = WTD_REVOKE_NONE;
	Trust_Data.dwUnionChoice = WTD_CHOICE_FILE;
	Trust_Data.dwStateAction = WTD_STATEACTION_VERIFY;
	Trust_Data.hWVTStateData = NULL;
	Trust_Data.pwszURLReference = NULL;
	Trust_Data.dwProvFlags = WTD_HASH_ONLY_FLAG;
	Trust_Data.dwUIContext = WTD_UICONTEXT_EXECUTE;

	//Verify
	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	long result = WinVerifyTrust(0, &WVTPolicyGUID, &Trust_Data);
	switch (result)
	{
	case 0:
		cout << "The file is signed and the signaturewas verified" << endl;
		return false;
	case TRUST_E_NOSIGNATURE:
		cout << "The file is not signed" << endl;
		break;
	case TRUST_E_EXPLICIT_DISTRUST:
		cout << "The signature is present, but specifically" << endl;
		break;
	case TRUST_E_SUBJECT_NOT_TRUSTED:
		cout << "The signature is present, but not trusted " << endl;
		break;
	case CRYPT_E_SECURITY_SETTINGS:
		cout << "CRYPT_E_SECURITY_SETTINGS - The hash " << endl;
		break;
	default:
		break;
	}

	return true;
}


bool Same_Export_Addr(PDWORD AddressOfFunction_Duplicate, int NumberOfFunctions, char* DLL_Name)
{
	DWORD Count = 0;
	for (int i = 0; i < NumberOfFunctions - 1; i++)
	{
		if (AddressOfFunction_Duplicate[i] == AddressOfFunction_Duplicate[i + 1])
		{
			Count++;
			if (i + 1 == NumberOfFunctions - 1)
			{
				break;
			}
			else if (AddressOfFunction_Duplicate[i + 1] == AddressOfFunction_Duplicate[i + 2])
			{
				SameExportAddr++;
				return true;
			}
		}
	}
	if (Count > 0)
	{
		SuspectedMalicious_DLL++;
		cout << "Suspected malicious DLL:\t" << DLL_Name << endl;
	}
	return false;
}


bool Same_Addr_Interval(PDWORD AddressOfFunction_Duplicate, int NumberOfFunctions)
{
	for (int i = 0; i < NumberOfFunctions - 3; i++)
	{
		DWORD interval = AddressOfFunction_Duplicate[i + 1] - AddressOfFunction_Duplicate[i];
		if ((AddressOfFunction_Duplicate[i + 2] - AddressOfFunction_Duplicate[i + 1]) == interval)
		{
			if ((AddressOfFunction_Duplicate[i + 3] - AddressOfFunction_Duplicate[i + 2]) == interval)
			{
				SameAddrInterval++;
				return true;
			}
		}
	}
	return false;
}


bool Same_Export_Name(char* Image_Address, PIMAGE_NT_HEADERS PImage_NT_Header, PDWORD AddressOfName, int NumberOfNames)
{
	for (int i = 0; i < NumberOfNames - 1; i++)
	{
		char* Function_Name_1 = Image_Address + RVA_To_FOA(PImage_NT_Header, AddressOfName[i]);
		for (int j = i + 1; j < NumberOfNames; j++)
		{
			char* Function_Name_2 = Image_Address + RVA_To_FOA(PImage_NT_Header, AddressOfName[j]);
			if (strcmp(Function_Name_1, Function_Name_2) == 0)
			{
				SameExportName++;
				return true;
			}
		}
	}
	return false;
}


int DLLHijack_Detection(char* Image_Address, PIMAGE_NT_HEADERS PImage_NT_Header)
{

	PIMAGE_EXPORT_DIRECTORY PImage_Export_Directory = NULL;
	char* DLL_Name = NULL;
	PDWORD AddressOfName = NULL;
	PWORD AddressOfNameOrdinals = NULL;
	PDWORD AddressOfFunction = NULL;
	
	Get_Export_Structure(Image_Address, PImage_NT_Header, &PImage_Export_Directory, &DLL_Name, &AddressOfName, &AddressOfNameOrdinals, &AddressOfFunction);
	
	DWORD Number_Of_Functions = PImage_Export_Directory->NumberOfFunctions;
	DWORD Number_Of_Names = PImage_Export_Directory->NumberOfNames;

	if (Number_Of_Functions == 0)
	{
		return 0;
	}
	
	PDWORD AddressOfFunction_Duplicate = new DWORD[Number_Of_Functions];
	for (int i = 0; i < Number_Of_Functions; i++)
	{
		AddressOfFunction_Duplicate[i] = AddressOfFunction[i];
	}

	//Sort Address Of Function Array(duplicate)
	Sort(&AddressOfFunction_Duplicate, Number_Of_Functions);

	//Detect
	if (Same_Export_Name(Image_Address, PImage_NT_Header, AddressOfName, Number_Of_Names))
	{
		Tread_Number++;
		cout << "DLLName:\t" << DLL_Name << "\t";
		cout << "\tDetected Trojan:\tTrojanHijacked.Win32.Agent\tReason:Same_Export_Name" << endl;
	}
	else if (Same_Export_Addr(AddressOfFunction_Duplicate, Number_Of_Functions,DLL_Name))
	{
		Tread_Number++;
		cout << "DLLName:\t" << DLL_Name << "\t";
		cout << "\tDetected Trojan:\tTrojanHijacked.Win32.Agent\tReason:Same_Export_Addr >= 3" << endl;
	}
	else if (Same_Addr_Interval(AddressOfFunction_Duplicate, Number_Of_Functions))
	{
		Tread_Number++;
		cout << "DLLName:\t" << DLL_Name << "\t";
		cout << "\tDetected Trojan:\tTrojanHijacked.Win32.Agent\tReason:Same_Addr_Interval >= 3" << endl;
	}

	return 0;
}


int main()
{
	string File_Path;
	string File_Path_Duplicate_A;
	string File_Path_Duplicate_B;
	cout << "File Path:";
	cin >> File_Path;
	File_Path += '\\';
	File_Path_Duplicate_A = File_Path;
	File_Path += '*';
	WIN32_FIND_DATAA File_Data;

	long Number_of_DLL_Detected = 0;
	int stage = 1;
	for (HANDLE HSearch = FindFirstFileA(File_Path.c_str(), &File_Data); stage; stage = FindNextFileA(HSearch, &File_Data))
	{
		if(File_Data.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
		{
			continue;
		}
		else
		{
			File_Path_Duplicate_B = File_Path_Duplicate_A + File_Data.cFileName;
		}

		HANDLE HFile = NULL;
		if (!(HFile = CreateFileA(File_Path_Duplicate_B.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
		{
			continue;
		}

		HANDLE HFMO = NULL;
		if (!(HFMO = CreateFileMappingA(HFile, NULL, PAGE_READONLY, 0, 0, NULL)))
		{
			CloseHandle(HFile);
			continue;
		}

		char* Image_Address = NULL;
		if (!(Image_Address = (char*)MapViewOfFile(HFMO, FILE_MAP_READ, 0, 0, 0)))
		{
			CloseHandle(HFMO);
			CloseHandle(HFile);
			continue;
		}

		PIMAGE_DOS_HEADER PImage_DOS_Header = (PIMAGE_DOS_HEADER)Image_Address;

		PIMAGE_NT_HEADERS PImage_NT_Header = (PIMAGE_NT_HEADERS)(Image_Address + PImage_DOS_Header->e_lfanew);

		//Determine whether it's a PE Structure,if it does,then whether it is a DLL file
		if ((PImage_DOS_Header->e_magic != IMAGE_DOS_SIGNATURE) || ((PImage_NT_Header->FileHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
		{
			UnmapViewOfFile(Image_Address);
			CloseHandle(HFMO);
			CloseHandle(HFile);
			continue;
		}

		if (PImage_NT_Header->OptionalHeader.DataDirectory[0].VirtualAddress == 0)
		{
			continue;
		}

		Number_of_DLL_Detected++;
		//Detect
		DLLHijack_Detection(Image_Address, PImage_NT_Header);

		CloseHandle(HFMO);
		CloseHandle(HFile);
	}
	cout << "Total Test Sample:\t" << Number_of_DLL_Detected << endl;
	cout << "Tread_Detected:\t" << Tread_Number << endl;
	cout << "SameAddressInterval:\t" << SameAddrInterval << endl;
	cout << "SameExportAddr:\t" << SameExportAddr << endl;
	cout << "SameExportName:\t" << SameExportName << endl;
	cout << "SuspectedMalicious_DLL:\t" << SuspectedMalicious_DLL << endl;
	getchar();
	getchar();
	return 0;
}

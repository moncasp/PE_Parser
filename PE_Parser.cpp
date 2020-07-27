#include <iostream>
#include<Windows.h>
#include<locale.h>
using namespace std;



void PImageHeaderWriter(PIMAGE_DOS_HEADER PImageHeader) {
	cout << endl << "______PIMAGE_DOS_HEADER______" << endl;
	cout << "e_magic : " << hex << PImageHeader->e_magic << endl;
	cout << "e_cblp : " << hex << PImageHeader->e_cblp << endl;
	cout << "e_cp : " << hex << PImageHeader->e_cp << endl;
	cout << "e_crlc : " << hex << PImageHeader->e_crlc << endl;
	cout << "e_cparhdr : " << hex << PImageHeader->e_cparhdr << endl;
	cout << "e_minalloc : " << hex << PImageHeader->e_minalloc << endl;
	cout << "e_maxalloc : " << hex << PImageHeader->e_maxalloc << endl;
	cout << "e_ss : " << hex << PImageHeader->e_ss << endl;
	cout << "e_sp : " << hex << PImageHeader->e_sp << endl;
	cout << "e_csum : " << hex << PImageHeader->e_csum << endl;
	cout << "e_ip : " << hex << PImageHeader->e_ip << endl;
	cout << "e_cs : " << hex << PImageHeader->e_cs << endl;
	cout << "e_lfarlc : " << hex << PImageHeader->e_lfarlc << endl;
	cout << "e_ovno : " << hex << PImageHeader->e_ovno << endl;
	cout << "e_res : " << hex << PImageHeader->e_res[3] << endl;
	cout << "e_oemid : " << hex << PImageHeader->e_oemid << endl;
	cout << "e_oeminfo : " << hex << PImageHeader->e_oeminfo << endl;
	cout << "e_res2 : " << hex << PImageHeader->e_res2[9] << endl;
	cout << "e_lfanew : " << hex << PImageHeader->e_lfanew << endl;
	cout << endl << endl << endl;
}

void ImageFileHeaderWriter(IMAGE_FILE_HEADER ImageFileHeader) {
	cout << endl << "______PIMAGE_FILE_HEADER______" << endl;
	cout << "Characteristics : " << hex << ImageFileHeader.Characteristics << endl;
	cout << "NumberOfSections : " << hex << ImageFileHeader.NumberOfSections << endl;
	cout << "TimeDateStamp : " << hex << ImageFileHeader.TimeDateStamp << endl;
	cout << "PointerToSymbolTable : " << hex << ImageFileHeader.PointerToSymbolTable << endl;
	cout << "NumberOfSymbols : " << hex << ImageFileHeader.NumberOfSymbols << endl;
	cout << "SizeOfOptionalHeader : " << hex << ImageFileHeader.SizeOfOptionalHeader << endl;
	cout << "Characteristics : " << hex << ImageFileHeader.Characteristics << endl;
	cout << endl << endl << endl;
}

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "Turkish");
	HANDLE fileHandle;

	if (argc == 1) {
		cout << "PE dosyası bulunamadı\n";
		return 0;
	}

	cout << "dosya parçalanıyor: " << argv[1] << endl;

	fileHandle = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		if (GetLastError() == 2) {
			cout << "Dosya Bulunamadı." << endl;
		}
		else {
			cout << "Dosya açma işlemi başarısız. Hata kodu: " << GetLastError();
		}
		return 0;
	}
    
    DWORD fileSize = GetFileSize(fileHandle, NULL);

	LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	
	if (fileData == NULL) {
		cout << "Doya için Hafızada Yer Ayrılamadı." << endl;
	}

	DWORD bytesRead;

	ReadFile(fileHandle, fileData, fileSize, &bytesRead, NULL);

	
	PIMAGE_DOS_HEADER PImageHeader = (PIMAGE_DOS_HEADER)fileData;
	PImageHeaderWriter(PImageHeader);

	PIMAGE_NT_HEADERS32 ntheader = (PIMAGE_NT_HEADERS32)(PImageHeader->e_lfanew + (LONG)fileData);
	cout << endl << "______PE_SIGNATURE______" << endl;
	cout << "PE SIGNATURE : " << hex << ntheader->Signature;
	cout << endl << endl;

	IMAGE_FILE_HEADER imageFileHeader = (IMAGE_FILE_HEADER )ntheader->FileHeader;
	ImageFileHeaderWriter(imageFileHeader);

	return 0;
}
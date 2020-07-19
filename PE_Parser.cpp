#include <iostream>
#include<Windows.h>
#include<locale.h>
using namespace std;

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

	return 0;
}
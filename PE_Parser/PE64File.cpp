#include "PE64File.h"
#include <print>

void PE64File::PrintInfo()
{
	//ParseFile();
	PrintDOSHeaderInfo();
	PrintRichHeaderInfo();
	PrintNTHeadersInfo();
	PrintSectionHeadersInfo();
	PrintImportTableInfo();
	PrintBaseRelocationsInfo();
}

int PE64File::INITPARSE()
{
	IMAGE_DOS_HEADER tmp_dos_header{};
	IMAGE_NT_HEADERS tmp_nt_header{};

	pe_file.seekg(std::ifstream::beg);

	pe_file.read((char*)&tmp_dos_header, sizeof(IMAGE_DOS_HEADER));

	if (tmp_dos_header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	pe_file.seekg(tmp_dos_header.e_lfanew, std::ifstream::beg);
	pe_file.read((char*)&tmp_nt_header, sizeof(IMAGE_NT_HEADERS));

	if (tmp_nt_header.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		pe_file.seekg(std::ifstream::beg);
		return 32;
	}

	if (tmp_nt_header.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pe_file.seekg(std::ifstream::beg);
		return 64;
	}

	return 0;
}

void PE64File::ParseFile()
{
	// PARSE DOS HEADER
	ParseDOSHeader();

	// PARSE RICH HEADER
	ParseRichHeader();

	//PARSE NT HEADERS
	ParseNTHeaders();

	// PARSE SECTION HEADERS
	ParseSectionHeaders();

	// PARSE IMPORT DIRECTORY
	ParseImportDirectory();

	// PARSE BASE RELOCATIONS
	ParseBaseReloc();
}

int PE64File::locate(DWORD VA) const
{
	size_t index{};

	for (size_t i{ 0 }; i < PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++)
	{
		if ((VA >= PEFILE_SECTION_HEADERS_VEC[i].VirtualAddress) && 
			(VA < PEFILE_SECTION_HEADERS_VEC[i].VirtualAddress + PEFILE_SECTION_HEADERS_VEC[i].Misc.VirtualSize))
		{
			index = i;
			break;
		}
	}

	return index;
}

DWORD PE64File::resolve(DWORD VA, int index)
{
	return (VA - PEFILE_SECTION_HEADERS_VEC[index].VirtualAddress) + PEFILE_SECTION_HEADERS_VEC[index].PointerToRawData;
}

void PE64File::ParseDOSHeader()
{
	pe_file.seekg(std::ifstream::beg);
	pe_file.read((char*)&PEFILE_DOS_HEADER, sizeof(IMAGE_DOS_HEADER));

	PEFILE_DOS_HEADER_EMAGIC = PEFILE_DOS_HEADER.e_magic;
	PEFILE_DOS_HEADER_LFANEW = PEFILE_DOS_HEADER.e_lfanew;
}

void PE64File::ParseNTHeaders()
{
	pe_file.seekg(PEFILE_DOS_HEADER.e_lfanew, std::ifstream::beg);
	pe_file.read((char*)&PEFILE_NT_HEADERS, sizeof(IMAGE_NT_HEADERS));

	PEFILE_NT_HEADERS_SIGNATURE = PEFILE_NT_HEADERS.Signature;

	PEFILE_NT_HEADERS_FILE_HEADER_MACHINE = PEFILE_NT_HEADERS.FileHeader.Machine;
	PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS = PEFILE_NT_HEADERS.FileHeader.NumberOfSections;
	PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER = PEFILE_NT_HEADERS.FileHeader.SizeOfOptionalHeader;

	PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC = PEFILE_NT_HEADERS.OptionalHeader.Magic;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE = PEFILE_NT_HEADERS.OptionalHeader.SizeOfCode;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA = PEFILE_NT_HEADERS.OptionalHeader.SizeOfInitializedData;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA = PEFILE_NT_HEADERS.OptionalHeader.SizeOfUninitializedData;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESSOF_ENTRYPOINT = PEFILE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_CODE = PEFILE_NT_HEADERS.OptionalHeader.BaseOfCode;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE = PEFILE_NT_HEADERS.OptionalHeader.ImageBase;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT = PEFILE_NT_HEADERS.OptionalHeader.SectionAlignment;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT = PEFILE_NT_HEADERS.OptionalHeader.FileAlignment;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE = PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage;
	PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS = PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders;

	PEFILE_EXPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PEFILE_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PEFILE_RESOURCE_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	PEFILE_EXCEPTION_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	PEFILE_SECURITY_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	PEFILE_BASERELOC_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PEFILE_DEBUG_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	PEFILE_ARCHITECTURE_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
	PEFILE_GLOBALPTR_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
	PEFILE_TLS_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	PEFILE_LOAD_CONFIG_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	PEFILE_BOUND_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	PEFILE_IAT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	PEFILE_DELAY_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	PEFILE_COM_DESCRIPTOR_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
}

void PE64File::ParseSectionHeaders()
{
	PEFILE_SECTION_HEADERS_VEC.resize(PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS);

	for (size_t i{ 0 }; i < PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++)
	{
		auto offset{ PEFILE_DOS_HEADER.e_lfanew + sizeof(PEFILE_NT_HEADERS) + (i * IMAGE_SIZEOF_SECTION_HEADER) };

		pe_file.seekg(offset, std::ifstream::beg);
		pe_file.read((char*)&PEFILE_SECTION_HEADERS_VEC[i], IMAGE_SIZEOF_SECTION_HEADER);
	}
}

void PE64File::ParseImportDirectory()
{

}

void PE64File::ParseBaseReloc()
{

}

void PE64File::ParseRichHeader()
{
	std::vector<char> buffer(PEFILE_DOS_HEADER_LFANEW);
	pe_file.seekg(std::ifstream::beg);
	pe_file.read(buffer.data(), PEFILE_DOS_HEADER_LFANEW);

	size_t index{};

	for (size_t i{ 0 }; i < (size_t)PEFILE_DOS_HEADER_LFANEW; i++)
	{
		if (buffer[i] == 'R' && buffer[i + 1] == 'i')
		{
			index = i;
			break;
		}
	}

	if (index == 0)
	{
		std::print("Error while parsing Rich Header.\n");
		PEFILE_RICH_HEADER_INFO.entries = 0;
		return;
	}

	char key[4]{};

	std::copy_n(buffer.begin() + index + 4, 
				4, 
				std::begin(key));

	size_t index_buff{ index - 4 };
	size_t rich_header_size{};

	while (true)
	{
		char tmp_buff[4]{};

		std::copy_n(buffer.begin() + index_buff, 
					4, 
					std::begin(tmp_buff));

		for (size_t i{ 0 }; i < 4; i++)
		{
			tmp_buff[i] = tmp_buff[i] ^ key[i];
		}

		index_buff -= 4;
		rich_header_size += 4;

		if (tmp_buff[0] == 'D' && tmp_buff[1] == 'a')
		{
			break;
		}
	}

	std::vector<char> rich_header_buffer(rich_header_size);

	std::copy_n(buffer.begin() + (index - rich_header_size), 
				rich_header_size, 
				rich_header_buffer.begin());


	for (size_t i{ 0 }; i < rich_header_size; i += 4)
	{
		for (size_t j{ 0 }; j < 4; j++)
		{
			rich_header_buffer[i + j] = rich_header_buffer[i + j] ^ key[j];
		}
	}

	PEFILE_RICH_HEADER_INFO.size = (int)rich_header_size;
	PEFILE_RICH_HEADER_INFO.entries = ((int)rich_header_size - 16) / 8;

	//PEFILE_RICH_HEADER.entries = new RICH_HEADER_ENTRY[PEFILE_RICH_HEADER_INFO.entries];	
	vec_entries.resize(PEFILE_RICH_HEADER_INFO.entries);


	for (size_t i{ 16 }; i < rich_header_size; i += 8)
	{
		WORD PRODID = (uint16_t)((BYTE)rich_header_buffer[i + 3] << 8) | (BYTE)rich_header_buffer[i + 2];
		WORD BUILDID = (uint16_t)((BYTE)rich_header_buffer[i + 1] << 8) | (BYTE)rich_header_buffer[i];
		DWORD USECOUNT = (uint32_t)((BYTE)rich_header_buffer[i + 7] << 24) | (BYTE)rich_header_buffer[i + 6] << 16 | (BYTE)rich_header_buffer[i + 5] << 8 | (BYTE)rich_header_buffer[i + 4];
		
		vec_entries[(i / 8) - 2] = { PRODID, BUILDID, USECOUNT };

		//if (i + 8 >= rich_header_size)
		//{
		//	//vec_entries[(i / 8) - 1] = { 0x0000, 0x0000, 0x00000000 };
		//}
	}

}

void PE64File::PrintFileInfo()
{

}

void PE64File::PrintDOSHeaderInfo()
{
	printf_s(" DOS HEADER:\n");
	printf_s(" -----------\n\n");
		  
	printf_s(" Magic: 0x%X\n", PEFILE_DOS_HEADER_EMAGIC);
	printf_s(" File address of new exe header: 0x%X\n", PEFILE_DOS_HEADER_LFANEW);
}

void PE64File::PrintRichHeaderInfo()
{
	printf(" RICH HEADER:\n");
	printf(" ------------\n\n");

	for (size_t i = 0; i < PEFILE_RICH_HEADER_INFO.entries; i++) {
		printf(" 0x%X 0x%X 0x%X: %d.%d.%d\n",
			vec_entries[i].buildID,
			vec_entries[i].prodID,
			vec_entries[i].useCount,
			vec_entries[i].buildID,
			vec_entries[i].prodID,
			vec_entries[i].useCount);
	}
}

void PE64File::PrintNTHeadersInfo()
{
	printf(" NT HEADERS:\n");
	printf(" -----------\n\n");

	printf(" PE Signature: 0x%X\n", PEFILE_NT_HEADERS_SIGNATURE);

	printf("\n File Header:\n\n");
	printf("   Machine: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_MACHINE);
	printf("   Number of sections: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS);
	printf("   Size of optional header: 0x%X\n", PEFILE_NT_HEADERS_FILE_HEADER_SIZEOF_OPTIONAL_HEADER);

	printf("\n Optional Header:\n\n");
	printf("   Magic: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_MAGIC);
	printf("   Size of code section: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_CODE);
	printf("   Size of initialized data: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_INITIALIZED_DATA);
	printf("   Size of uninitialized data: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_UNINITIALIZED_DATA);
	printf("   Address of entry point: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_ADDRESSOF_ENTRYPOINT);
	printf("   RVA of start of code section: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_BASEOF_CODE);
	printf("   Desired image base: 0x%llX\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_IMAGEBASE);
	printf("   Section alignment: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SECTION_ALIGNMENT);
	printf("   File alignment: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_FILE_ALIGNMENT);
	printf("   Size of image: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_IMAGE);
	printf("   Size of headers: 0x%X\n", PEFILE_NT_HEADERS_OPTIONAL_HEADER_SIZEOF_HEADERS);

	printf("\n Data Directories:\n");
	printf("\n   * Export Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_EXPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_EXPORT_DIRECTORY.Size);

	printf("\n   * Import Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_IMPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_IMPORT_DIRECTORY.Size);

	printf("\n   * Resource Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_RESOURCE_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_RESOURCE_DIRECTORY.Size);

	printf("\n   * Exception Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_EXCEPTION_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_EXCEPTION_DIRECTORY.Size);

	printf("\n   * Security Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_SECURITY_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_SECURITY_DIRECTORY.Size);

	printf("\n   * Base Relocation Table:\n");
	printf("       RVA: 0x%X\n", PEFILE_BASERELOC_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_BASERELOC_DIRECTORY.Size);

	printf("\n   * Debug Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_DEBUG_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_DEBUG_DIRECTORY.Size);

	printf("\n   * Architecture Specific Data:\n");
	printf("       RVA: 0x%X\n", PEFILE_ARCHITECTURE_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_ARCHITECTURE_DIRECTORY.Size);

	printf("\n   * RVA of GlobalPtr:\n");
	printf("       RVA: 0x%X\n", PEFILE_GLOBALPTR_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_GLOBALPTR_DIRECTORY.Size);

	printf("\n   * TLS Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_TLS_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_TLS_DIRECTORY.Size);

	printf("\n   * Load Configuration Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_LOAD_CONFIG_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_LOAD_CONFIG_DIRECTORY.Size);

	printf("\n   * Bound Import Directory:\n");
	printf("       RVA: 0x%X\n", PEFILE_BOUND_IMPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_BOUND_IMPORT_DIRECTORY.Size);

	printf("\n   * Import Address Table:\n");
	printf("       RVA: 0x%X\n", PEFILE_IAT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_IAT_DIRECTORY.Size);

	printf("\n   * Delay Load Import Descriptors:\n");
	printf("       RVA: 0x%X\n", PEFILE_DELAY_IMPORT_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_DELAY_IMPORT_DIRECTORY.Size);

	printf("\n   * COM Runtime Descriptor:\n");
	printf("       RVA: 0x%X\n", PEFILE_COM_DESCRIPTOR_DIRECTORY.VirtualAddress);
	printf("       Size: 0x%X\n", PEFILE_COM_DESCRIPTOR_DIRECTORY.Size);
}

void PE64File::PrintSectionHeadersInfo()
{
	printf(" SECTION HEADERS:\n");
	printf(" ----------------\n\n");

	for (size_t i{ 0 }; i < PEFILE_NT_HEADERS_FILE_HEADER_NUMBER0F_SECTIONS; i++) {
		printf("   * %.8s:\n", PEFILE_SECTION_HEADERS_VEC[i].Name);
		printf("        VirtualAddress: 0x%X\n", PEFILE_SECTION_HEADERS_VEC[i].VirtualAddress);
		printf("        VirtualSize: 0x%X\n", PEFILE_SECTION_HEADERS_VEC[i].Misc.VirtualSize);
		printf("        PointerToRawData: 0x%X\n", PEFILE_SECTION_HEADERS_VEC[i].PointerToRawData);
		printf("        SizeOfRawData: 0x%X\n", PEFILE_SECTION_HEADERS_VEC[i].SizeOfRawData);
		printf("        Characteristics: 0x%X\n\n", PEFILE_SECTION_HEADERS_VEC[i].Characteristics);
	}
}

void PE64File::PrintImportTableInfo()
{

}

void PE64File::PrintBaseRelocationsInfo()
{

}

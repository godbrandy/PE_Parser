// PE_Parser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <filesystem>
#include <print>
#include <fstream>
#include "PE64File.h"

namespace fs = std::filesystem;

int main()
{
    fs::path file_path;
    std::string name;

    std::print("Insert the path of the file: ");
    std::getline(std::cin, name);
    file_path = name;

    if (!fs::exists(file_path) || !fs::is_regular_file(file_path))
    {
        std::print("File not found.\n");
        return -1;
    }

    std::ifstream buffer(file_path, std::ios::binary);

    if (!buffer)
    {
        std::print("Failed to open file.\n");
        return -1;
    }

    PE64File pe_file{ file_path.string(), std::move(buffer) };

    int bitness{ pe_file.INITPARSE() };
    if (bitness == 0)
    {
        std::print("Invalid PE file.\n");
    }

    else if (bitness == 32)
    {
        std::print("32-bit PE file.\n\n");
        pe_file.PrintInfo();
    }

    else if (bitness == 64)
    {
        std::print("64-bit PE file.\n\n");
        pe_file.PrintInfo();
    }

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

#include <cstdint>
#include <filesystem>
#include <vector>
#include <fstream>

#include <fmt/core.h>
#include <zip.h>

int main()
{
    fmt::println("PKWARE Attack");

    std::filesystem::path path = "./secrets.zip";

    zip_t* zip = zip_open(path.string().c_str(), ZIP_RDONLY, 0);

    int errorCode;

    if (!zip)
    {
        zip_error_t error;
        zip_error_init_with_code(&error, errorCode);

        fmt::println("Failed to open zip: {}", zip_error_strerror(&error));
        zip_error_fini(&error);

        return 1;
    }

    fmt::println("Zip OK");

    int64_t numEntries = zip_get_num_entries(zip, 0);

    fmt::println("Zip has: {} entries.", numEntries);


    std::vector<zip_stat_t> entries;
    entries.reserve(numEntries);

    for (uint64_t i = 0; i < numEntries; i++)
    {
        /*zip_stat_init(&entries[i]);

        if (!&entries[i])
            fmt::println("Failed to initialize stat");
        */

        zip_stat_t fileStat;
        zip_stat_init(&fileStat);

        if (zip_stat_index(zip, i, 0, &fileStat) == 0)
        {
            entries.push_back(fileStat);

            fmt::println("name: {}", entries[i].name);
            fmt::println("size: {}", entries[i].size);
        }
    }

    if (entries.empty())
    {
        fmt::println("No files inside the zip.");
        zip_close(zip);
        return 0;
    }



    for (uint64_t i = 0; i < numEntries; i++)
    {

        zip_file_t* file = zip_fopen_index_encrypted(zip, i, 0, "W4sF0rgotten");

        if (!file)
        {
            fmt::println("Failed read file at index {}", 0);
            zip_close(zip);
            return 1;
        }

        std::vector<uint8_t> data(entries[i].size);

        int64_t byteRead = zip_fread(file, data.data(), entries[i].size);


        fmt::println("num of bytes: {}", byteRead);





        std::filesystem::path fileName = entries[i].name;

        std::fstream exportFile(fileName.string(), std::ios::binary | std::ios::out);

        if (exportFile.is_open())
        {
            exportFile.write(reinterpret_cast<char*>(data.data()), data.size());
        }
        else
        {
            fmt::println("Failed to open export file");
        }

        exportFile.close();
    }

    zip_close(zip);





    /*
    zip_file_t* file = zip_fopen_index_encrypted(zip, 0, 0, "W4sF0rgotten");

    if (!file)
    {
        fmt::println("Failed read file at index {}", 0);
        zip_close(zip);
        return 1;
    }

    std::vector<uint8_t> data(entries[0].size);

    int64_t byteRead = zip_fread(file, data.data(), entries[0].size);


    fmt::println("num of bytes: {}", byteRead);


    zip_close(zip);


    std::filesystem::path fileName = "advice.jpg";

    std::fstream exportFile(fileName.string(), std::ios::binary | std::ios::out);

    if (exportFile.is_open())
    {
        exportFile.write(reinterpret_cast<char*>(data.data()), data.size());
        exportFile.close();
    }
    else
    {
        fmt::println("Failed to open export file");
    }
    */


}
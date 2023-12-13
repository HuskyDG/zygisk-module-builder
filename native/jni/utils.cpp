#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <vector>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>

#include "utils.hpp"

std::vector<MapInfo> scan_maps() {
    std::vector<MapInfo> maps;
    MapInfo map;
    FILE *fp = fopen("/proc/self/maps", "re");
    if (fp == nullptr) return maps;
    char line[4098];
    while (fgets(line, sizeof(line), fp)) {
        char path[4098];
        char perms[10];
        char addr[50];
        unsigned int major_dev, minor_dev, path_start;
        sscanf(line, "%s %s %ld %x:%x %ld %n%*s", addr, perms, &map.offset, &major_dev, &minor_dev, &map.inode, &path_start);
        map.dev = makedev(major_dev, minor_dev);
        line [strlen(line) - 1] = '\0';
        map.path = line + path_start;
        map.perms = 0;
        map.is_private = false;
        if (strchr(perms, 'r')) map.perms |= PROT_READ;
        if (strchr(perms, 'w')) map.perms |= PROT_WRITE;
        if (strchr(perms, 'x')) map.perms |= PROT_EXEC;
        if (strchr(perms, 'p')) map.is_private = true;
        char *addr2 = strchr(addr, '-');
        *addr2 = '\0';
        addr2++;
        map.start = 0; map.end = 0;
        for (int i=0; addr[i]; i++) {
            map.start *= 16;
            int x = 0;
            if (addr[i] >= 'a' && addr[i] <= 'f') {
                x = addr[i] - 'a' + 10;
            } else if (addr[i] >= '0' && addr[i] <= '9') {
                x = addr[i] - '0';
            }
            map.start += x;
        }
        for (int i=0; addr2[i]; i++) {
            map.end *= 16;
            int x = 0;
            if (addr2[i] >= 'a' && addr2[i] <= 'f') {
                x = addr[i] - 'a' + 10;
            } else if (addr2[i] >= '0' && addr2[i] <= '9') {
                x = addr2[i] - '0';
            }
            map.end += x;
        }
        printf("%s\n", line);
        printf("%s\n", map.path.data());
        maps.emplace_back(map);
    }
    fclose(fp);
    return maps;
}

int read_int(int fd) {
    int val;
    if (read(fd, &val, sizeof(val)) != sizeof(val))
        return -1;
    return val;
}

void write_int(int fd, int val) {
    if (fd < 0) return;
    write(fd, &val, sizeof(val));
}

bool read_string(int fd, std::string &str) {
    int len = read_int(fd);
    str.clear();
    if (len < 0)
        return false;
    str.resize(len);
    return read(fd, str.data(), len) == len;
}

std::string read_string(int fd) {
    std::string str;
    read_string(fd, str);
    return str;
}

void write_string(int fd, std::string_view str) {
    if (fd < 0) return;
    write_int(fd, str.size());
    write(fd, str.data(), str.size());
}

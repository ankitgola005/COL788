/*  Ankit Gola
 *  2017EET2296
 *
 *  Client code
 */

// Include files
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>

#include "vars.h"
#include "utils.h"
#include "log.h"

// Enumerate valid commands
enum USER_CMD {
    USER_INVALID = -1,
    USER_LS = 0,
    USER_PWD,
    USER_CD,
    USER_CDUP,
    USER_RENAME,
    USER_PUT,
    USER_GET,
    USER_USER,
    USER_PASS,
    USER_TYPE,
    USER_BYE,
    USER_MKD,
    USER_DELE,
    USER_RNFR,
    USER_RNTO,
    USER_RMD,
    USER_LCD,
    USER_LLS,
    USER_LPWD,
    USER_HELP,
    USER_COUNT
};

// Struct for valid ftp commands
struct ftp_cmd USER_CMD_LIST[USER_COUNT] = {
    {"LS", USER_LS},
    {"PWD", USER_PWD},
    {"CD", USER_CD},
    {"CDUP", USER_CDUP},
    {"RENAME", USER_RENAME},
    {"PUT", USER_PUT},
    {"GET", USER_GET},
    {"USER", USER_USER},
    {"PASS", USER_PASS},
    {"TYPE", USER_TYPE},
    {"BYE", USER_BYE},
    {"MKD", USER_MKD},
    {"DELE", USER_DELE},
    {"RNFR", USER_RNFR},
    {"RNTO", USER_RNTO},
    {"RMD", USER_RMD},
    {"LCD", USER_LCD},
    {"LLS", USER_LLS},
    {"LPWD", USER_LPWD},
    {"HELP", USER_HELP}
};

// Parse user input
enum USER_CMD parse_input_cmd(char* buf, int len) {
    int i, j;
    // Read input
    for (i=0; i<sizeof(USER_CMD_LIST)/sizeof(USER_CMD_LIST[0]); i++) {
        for(j=0; USER_CMD_LIST[i].name[j] && j < len; j++) {
            // If user command is valid
            if (USER_CMD_LIST[i].name[j] != buf[j] & 0x1f && USER_CMD_LIST[i].name[j] != buf[j]- 32) 
                break;
        }
        // Return the command
        if (USER_CMD_LIST[i].name[j] == '\0' && (buf[j]==' ' || buf[j]==0))
            return USER_CMD_LIST[i].cmd;
    }
    // Else if command is invalid
    return USER_INVALID;
}

// Enumerate client state
enum CLIENT_STATE {
    ST_NONE,
    ST_PASVLIST,
    ST_PASVLIST2,
    ST_PASVGET,
    ST_PASVGET2,
    ST_PASVPUT,
    ST_PASVPUT2
};

// Initialise client
int running = 1;

// Set running to 0 to kill the client
void ouch() {
    running = 0;
}

// Main
int main(int argc, char *argv[]) {
    // Default server
    int server_port = 2121;
    
    // If proper args are not supplied
    if (argc < 2) {
        printf("usage: %s <addr> [2121]\n", argv[0]);
        exit(0);
    }

    // If different port is suplied
    if (argc == 3) {
        server_port = atoi(argv[2]);
    }

    // Create new client
    int client = new_client(ntohl(inet_addr(argv[1])), server_port);
    if (client < 0) {
        err(1, "can not connect to %s %d", argv[1], server_port);
        err(1, "exit ...");
        exit(1);
    }
    
    // Default parameters
    int i, n;
    char buf[BUF_SIZE+1];
    char tmpbuf[BUF_SIZE+1];
    char cmdbuf[BUF_SIZE+1];
    int data_client = -1;
    struct sockaddr_in data_client_addr;
    uint32_t addr;
    uint16_t port;
    char path[BUF_SIZE];
    int code = -1;
    enum CLIENT_STATE state = ST_NONE;
    char filename[BUF_SIZE], line[BUF_SIZE];

    // While data is recieved
    while ((n=recv(client, buf, sizeof(buf), MSG_PEEK)) > 0) {
        // If not running
        if (!running) break;

        // Get size of buffer
        for (i=0; i<n; i++) {
            if (buf[i] == '\n') break;
        }

        // If no line breaks found
        if (buf[i] != '\n') {
            err(1, "no line break found");
            break;
        }

        // Recieve i bits of data in buf, parse buf, and set the command code of FTP
        n = recv(client, buf, i+1, 0);
        buf[n] = 0;
        printf("%s", buf);
        fflush(stdout);
        parse_number(buf, &code);
        
        // If command is known
        if (code < RPL_ERR_UNKWNCMD && state != ST_NONE) {
            // Switch
            switch(state) {
                // Passive state
                case ST_PASVLIST:

                // Passive get from server
                case ST_PASVGET:
                
                // Passive put from server
                case ST_PASVPUT:
                    if (code == RPL_PASVOK) {
                        strcpy(tmpbuf, buf);
                        tmpbuf[0] = tmpbuf[1] = tmpbuf[2] = tmpbuf[3] = ' ';
                        parse_addr_port(tmpbuf, &addr, &port);
                        
                        // Handle passive commands
                        switch(state) {
                            case ST_PASVLIST:
                                send_str(client, "LIST\r\n");
                                break;
                            case ST_PASVGET:
                                send_str(client, "RETR %s\r\n", filename);
                                break;
                            case ST_PASVPUT:
                                send_str(client, "STOR %s\r\n", filename);
                                break;
                        }
                        data_client = new_client(addr, port);
                        state++;
                    } else {
                        state = ST_NONE;
                    }
                    break;

                // Passive mode
                case ST_PASVLIST2:
                case ST_PASVGET2:
                case ST_PASVPUT2:
                    // If client is not created
                    if (data_client < 0) {
                        err(1, "data client not created");
                    } 
                    // Else handle pasv commands
                    else {
                        if (state == ST_PASVLIST2) {
                            recv_file(data_client, stdout);
                        } else if (state == ST_PASVGET2) {
                            recv_path(data_client, filename, 0);
                        } else if (state == ST_PASVPUT2) {
                            FILE *f = fopen(filename, "rb");
                            if (f) {
                                send_file(data_client, f);
                                fclose(f);
                            } else {
                                err(1, "err open file %s", filename);
                            }
                        }
                        info(1, "closing data socket ... %d", close(data_client));
                        data_client = -1;
                        state = ST_NONE;
                    }
                    break;

                // Default case
                default:
                    state = ST_NONE;
                    break;
            }
            // Loop
            if (code < RPL_ERR_UNKWNCMD)
                continue;
        }

        // If code exceeds unknown command state, set state to none
        if (code >= RPL_ERR_UNKWNCMD) state = ST_NONE;

        // Loop while valid is 0
        int valid = 0;
        while (!valid) {
            valid = 1;

            // Read user input
            printf("ftp >>> ");
            if (!fgets(line, BUF_SIZE, stdin)){
                running = 0;
                break;
            }

            // Parse input
            int len = strlen(line);
            len --;
            while (line[len] == '\n' || line[len] == '\r') len--;
            len ++;
            line[len] = 0;

            // Get user command number
            enum USER_CMD cmd = parse_input_cmd(line, len);
            
            // Switch cmd as per parsed user input nad handle the command
            switch(cmd) {
                // Supply Username
                case USER_USER:

                // Supply password
                case USER_PASS:

                // Transfer mode
                case USER_TYPE:

                // Make directory
                case USER_MKD:

                // Delete file
                case USER_DELE:

                // Rename from
                case USER_RNFR:

                // Rename to
                case USER_RNTO:
                
                // Remove directory
                case USER_RMD:
                    send_str(client, "%s\r\n", line);
                    break;

                // ls on server
                case USER_LS:
                    send_str(client, "PASV\r\n");
                    state = ST_PASVLIST;
                    break;

                // cd on server
                case USER_CD:
                    send_str(client, "CWD %s\r\n", &line[3]);
                    break;

                // pwd on server
                case USER_PWD:
                    send_str(client, "PWD\r\n");
                    break;

                // Switch to parent directory, if valid
                case USER_CDUP:
                    send_str(client, "CDUP\r\n");
                    break;

                // Print help menu
                case USER_HELP:
                    //for (i=0; i<sizeof(USER_CMD_LIST)/sizeof(USER_CMD_LIST[0]); i++) {
                    //    printf("%s\n", USER_CMD_LIST[i].name);
                    //}
                    printf("user    :   Supply username to server\n");
                    printf("pass    :   Supply password for the said user to server\n");
                    printf("ls      :   List files and folders on server\n");
                    printf("pwd     :   Change curernt working directory on server\n");
                    printf("cd      :   Chande directory on server\n");
                    printf("cdup    :   Switch to parent directory on server\n");
                    printf("rename  :   Rename file/folder on server\n");
                    printf("put     :   Put a file on server\n");
                    printf("get     :   Get a file from server\n");
                    printf("type    :   Change connection type\n");
                    printf("mkd     :   Get a file from server\n");
                    printf("dele    :   Delete a file from server\n");
                    printf("rnfr    :   Start renaming a file on server\n");
                    printf("rnto    :   Stop renaming  a file on server\n");
                    printf("rmd     :   Delete a directory from server\n");
                    printf("lcd     :   Local cd on client\n");
                    printf("lls     :   Local ls on client\n");
                    printf("lpwd    :   Local pwd on client\n");
                    printf("bye     :   Close the connection to server\n");
                    printf("help    :   Print help menu\n");
                    
                    valid = 0;
                    break;

                // Close client connection
                case USER_BYE:
                    send_str(client, "QUIT\r\n");
                    running = 0;
                    break;

                // Local cd on client
                case USER_LCD:
                    chdir(&line[4]);
                    valid = 0;
                    break;

                // Local ls on client
                case USER_LLS:
                    getcwd(path, sizeof(path));
                    printf("%s\n", path);

                    sprintf(cmdbuf, "ls -l %s", path);
                    FILE *p2 = popen(cmdbuf, "r");
                    int n;
                    while ((n=fread(tmpbuf, 1, BUF_SIZE, p2)) > 0 ) {
                        fwrite(tmpbuf, 1, n, stdout);
                    }
                    pclose(p2);

                    valid = 0;
                    break;

                // Local pwd on client
                case USER_LPWD:
                    getcwd(path, sizeof(path));
                    printf("%s\n", path);
                    valid = 0;
                    break;

                // Get file from serevr
                case USER_GET:
                    send_str(client, "PASV\r\n");
                    strcpy(filename, &line[4]);
                    state = ST_PASVGET;
                    break;

                // Put file on server
                case USER_PUT:
                    send_str(client, "PASV\r\n");
                    strcpy(filename, &line[4]);
                    state = ST_PASVPUT;
                    break;

                // Default
                default:
                    warn(1, "unknown user cmd");
                    valid = 0;
                    break;
            }
        }

        // If not running, exit client loop
        if (!running) break;
    }

    // Close client
    int st = close(client);
    info(1, "FTP client close socket ... %d", st);
    info(1, "FTP client shutdown");
    if (data_client > 0) {
        st = close(data_client);
        info(1, "FTP client close data socket ... %d", st);
        info(1, "FTP client data socket shutdown");
    }
    return 0;
}


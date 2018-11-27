/*  Ankit Gola
 *  2017EET2296
 *
 *  Server file
 */

// Includes
#include <stdio.h>
#include <unistd.h>
#include <shadow.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <crypt.h>

#include "vars.h"
#include "log.h"
#include "utils.h"

#define _XOPEN_SOURCE

// Initialisations
int server = -1, client = -1, running = 0;
pid_t forkpid = 1;
char buf[BUF_SIZE];

/* handle Ctrl-C 
 * @param {int} socket fd
 * The parent and all its children will recieve kill signal and execute this
 */
void ouch(int n) {
    running = 0;
    puts("");
    // Close Server
    if (forkpid > 0) {
        if (server >= 0) {
            int st = close(server);
            info(0, "shutdown ftp ... %d", st);
        }

    // Kill client session
    } else {
        if (client >= 0) {
            int st = close(client);
            info(1, "shutdown ftp session... %d", st);
        }
    }
    exit(0);
}

/* Parse FTP commands
 * If comand recognised, send that, else send invalid 
 */
enum FTP_CMD parse_cmd(char *buf, int len) {
    int i,j;
    for (i = 0; i < FTP_CMD_COUNT; i++) {
        for (j = 0; FTP_CMD_LIST[i].name[j] != '\0' && j < len; j++) {
            if (FTP_CMD_LIST[i].name[j] != buf[j] && FTP_CMD_LIST[i].name[j] != buf[j]-32) break;
        }
        if (FTP_CMD_LIST[i].name[j] == '\0')
            return FTP_CMD_LIST[i].cmd;
    }
    return INVALID;
}

/* Handle a newly accepted ftp session
 */
void handle_session(int client) {
    // FTP ready
    send_str(client, FTP_RDY);
    int i, n, retry;
    char cwd[BUF_SIZE] = {0}, cmdbuf[BUF_SIZE] = {0};
    enum DATA_TYPE datatype = TYPE_IMAGE;
    srand(time(0));
    uint32_t pasv_port;
    enum TRSF_TYPE trsf_type = TRSF_PORT;
    int pasv_server = -1;
    
    // Socket and initialisations
    struct sockaddr_in svr_addr;
    int svr_addr_len = sizeof(svr_addr);
    getsockname(client, (struct sockaddr*)&svr_addr, &svr_addr_len);
    uint32_t svr_host_addr = ntohl(svr_addr.sin_addr.s_addr);
    uint32_t port_address = 0;
    uint16_t port_port = 0;
    int data_client = -1;
    struct sockaddr_in data_client_addr;
    int data_client_len = sizeof(data_client_addr);
    uint32_t restdata = 0;
    char rnfr[BUF_SIZE];
    char *p = NULL;         // tmp file path
    struct stat file_stat;  // file stat for time and size
    struct tm mdtime;

    /* Variables for login process */
    char *input_id;         // user name
    char *input_pw;         // password
    char *input_hash;       // hash generated with input id & pw
    char shadow_salt[BUF_SIZE];
    struct spwd *shadow;
    struct passwd *passwd_data;
    int count;
    int flag=0;             // 0: not logined  1: id check  2: logined

    // Loop and listen to client
    while ((n=recv(client, buf, BUF_SIZE, MSG_PEEK)) > 0) {
        if (!running) break;
        buf[n] = '\0';
        //info(1, "recved %d bytes: %s", n, buf);
        for (i=0; i<n; i++) {
            if (buf[i] == '\n') break;
        }
        if (buf[i] != '\n') {
            err(1, "no line break found");
            break;
        }
        
        // Recieve buffer from client
        n = recv(client, buf, i+1, 0);
        buf[n] = '\0';

        // Parse FTP command
        enum FTP_CMD cmd = parse_cmd(buf, n);
        if (cmd < 0) {
            buf[n-2] = 0;
            err(1, "unknown cmd: %s", buf);
            continue;
        }

        // Check if client is logged in
        info(1, "cmd: %s, %d", FTP_CMD_LIST[cmd].name, cmd);
        if (flag == 0 && cmd != USER && cmd != QUIT || flag == 1 && cmd != PASS && cmd != QUIT){
            send_str(client, FTP_NEED_LOGIN);
        }
        // Else parse commands. Note that these are not the commands supported by the server, but more of auxiliary functions.
        // For a list of supported commands, use help
        else {
            switch(cmd) {
                // If FTP is working, elicit a response from the server
                case NOOP:
                    send_str(client, FTP_OK);
                    break;

                // Close client connection
                case QUIT:
                    send_str(client, FTP_QUIT);
                    running = 0;
                    flag = 0;
                    break;
                
                // Print help text
                case HELP:
                    send_str(client, FTP_HELP);
                    break;

                // Input user name
                case USER:
                    input_id = buf;

                    // cut id
                    while(*(input_id-1) != ' ') input_id++;
                    // remove <CRLF>
                    for (i = 0; i<strlen(input_id);i++){
                        if (input_id[i] == '\r' || input_id[i] == '\n')
                            input_id[i] = 0;
                    }

                    // get shadow data from /etc/shadow. This reads username from OS
                    shadow = getspnam(input_id);
                    if (shadow){
                        send_str(client, FTP_NAMEOK);
                        info(1,"user %s trying to login...",shadow->sp_namp);
                        flag = 1;
                    }
                    else {
                        send_str(client, FTP_ERR_NAME);
                        info(1, "%s login failed.", input_id);
                    }
                    break;

                // Input user pasword
                case PASS:
                    input_pw = buf;

                    // cut pw
                    while (*(input_pw-1) != ' ') input_pw++;
                    // remove <CRLF>
                    for (i=0;i<strlen(input_pw);i++)
                        if (input_pw[i] == '\r' || input_pw[i] == '\n')
                            input_pw[i] = 0;

                    // get salt from shadow data, salt is the additional random data to hash function
                    count = 0;
                    for(i = 0; i < 3;){
                        if (shadow->sp_pwdp[count++] == '$')
                            i++;
                    }
                    strncpy(shadow_salt, shadow->sp_pwdp, count);
                    input_hash = crypt(input_pw, shadow_salt);

                    if (strcmp(input_hash, shadow->sp_pwdp) == 0){
                        send_str(client, FTP_LOGIN);
                        info(1, "user %s logged in.", shadow->sp_namp);

                        // get data from /etc/passwd for uid and gid
                        passwd_data = getpwnam(shadow->sp_namp);
                        setgid(passwd_data->pw_gid);
                        setuid(passwd_data->pw_uid);
                        flag = 2;
                    }

                    else {
                        send_str(client, FTP_LOGIN_FAIL);
                        info(1, "user %s:%s logged in fail.", shadow->sp_namp,input_pw);
                        flag = 0;
                    }
                    break;
                
                // Get pwd 
                case PWD:
                    getcwd(cwd, sizeof(cwd));
                    send_str(client, FTP_PWD, cwd);
                    break;

                // Query server OS
                case SYST:
                    send_str(client, FTP_SYST);
                    break;

                // to change type of data to be sent
                case TYPE:
                    if (buf[5] == 'A') {
                        datatype = TYPE_ASCII;
                        send_str(client, FTP_CTYPE, buf[5]);
                    } else if (buf[5] == 'I') {
                        datatype = TYPE_IMAGE;
                        send_str(client, FTP_CTYPE, buf[5]);
                    } else {
                        send_str(client, FTP_ERR_DATATYPE, datatype == TYPE_ASCII ? 'A' : 'I');
                    }
                    break;

                // Tell server to enter passive mode
                case PASV:
                    retry = 100;
                    while (retry--) { // in case of create server error, port used
                        pasv_port = (rand() % 64512 + 1024);
                        trsf_type = TRSF_PASV;
                        pasv_server = new_server(INADDR_ANY, pasv_port, 1);
                        if (pasv_server >= 0) break;
                    }
                    if (pasv_server < 0) {
                        err(1, "can not create pasv port for passive mode");
                        // TODO: send err msg here
                    } else {
                        info(1, "PASV server created, port : %hu", pasv_port);
                        uint32_t t = svr_addr.sin_addr.s_addr;
                        send_str(client, FTP_PASV, t&0xff, (t>>8)&0xff, (t>>16)&0xff, (t>>24)&0xff, pasv_port>>8, pasv_port & 0xff);
                    }
                    break;

                // Establish a new connection at the new specifed port number
                case PORT:
                    trsf_type = TRSF_PORT;
                    int _st = parse_addr_port(buf, &port_address, &port_port);
                    if (!_st) {
                        err(1, "port cmd error parsing addr and port");
                        send_str(client, FTP_ERR_PORT);
                    } else {
                        info(1, "address is %s, port is %ld", n2a(port_address), port_port);
                        send_str(client, FTP_PORT);
                    }
                    break;

                // Information of current pwd 
                case LIST:
                    // If in passive mode
                    if (trsf_type == TRSF_PASV) {
                        if (pasv_port > 1024 && pasv_port <= 65535 && pasv_server >= 0) {
                            send_str(client, FTP_ASCII, "LIST");
                            data_client = accept(pasv_server, (struct sockaddr *)&data_client_addr, &data_client_len);
                            if (data_client < 0) {
                                err(1, "LIST, accept data client socket error");
                            }
                        } else {
                            err(1, "LIST, no pasv server created");
                            break;
                        }
                    // Transfer mode
                    } else if (trsf_type == TRSF_PORT) {
                        if (port_address == 0 || port_port == 0) {
                            err(1, "LIST, in PORT mode, address and port not set before");
                            break;
                        }
                        send_str(client, FTP_ASCII, "LIST");
                        info(1, "LIST, in PORT mode, try connecting %s %lu", n2a(port_address), port_port);
                        data_client = new_client(port_address, port_port);
                        if (data_client < 0) {
                            err(1, "port mode connect client data sock error");
                            break;
                        } else {
                            info(1, "LIST, in PORT mode, %s %lu connected", n2a(port_address), port_port);
                        }
                    // No transfer type specified
                    } else {
                        err(1, "LIST: transfer type no specified");
                    }
                    
                    // If data client is created
                    if (data_client >= 0) {
                        // Get pwd/file/folder data
                        getcwd(cwd, sizeof(cwd));
                        sprintf(cmdbuf, "ls -l %s", cwd);
                        FILE *p1 = popen(cmdbuf, "r");
                        
                        // Send data to client
                        send_file(data_client, p1);
                        send_str(client, FTP_TRSF_OK);
                        pclose(p1);
                        info(1, "LIST , data client closed, status %d", close(data_client));
                        data_client = -1;
                    } else {
                        err(1, "LIST , no data client created");
                    }
                    // Close the passive connection
                    if (pasv_server >= 0) {
                        info(1, "LIST, closing passive server ... %d", close(pasv_server));
                        pasv_server = -1;
                    }
                    break;

                // Restart transfer from specified point
                case REST:
                    if (parse_number(buf, &restdata) == 0) {
                        send_str(client, FTP_REST, restdata);
                    } else {
                        err(1, "REST, command error, wrong param");
                        send_str(client, FTP_ERR_PARAM, "REST");
                    }
                    break;

                // Retrieve a copy of the file
                case RETR:
                    // Passive transfer
                    if (trsf_type == TRSF_PASV) {
                        // If passive port is ready
                        if (pasv_port > 1024 && pasv_port <= 65535 && pasv_server >= 0) {
                            if (datatype == TYPE_ASCII) {
                                send_str(client, FTP_ASCII, "RETR");
                            } else {
                                send_str(client, FTP_BIN, "RETR");
                            }
                            data_client = accept(pasv_server, (struct sockaddr *)&data_client_addr, &data_client_len);
                            if (data_client < 0) {
                                err(1, "accept data client error");
                                break;
                            }
                        // Passive port not ready
                        } else {
                            err(1, "RETR, pasv server not ready ");
                        }

                    // For transfer port
                    } else if (trsf_type == TRSF_PORT) {
                        // Addresss and port not set
                        if (port_address == 0 || port_port == 0) {
                            err(1, "RETR, in PORT mode, address and port not set before");
                            break;
                        }
                        if (datatype == TYPE_ASCII) {
                            send_str(client, FTP_ASCII, "RETR");
                        } else {
                            send_str(client, FTP_BIN, "RETR");
                        }
                        info(1, "RETR , PORT mode, try connecting %s %lu", n2a(port_address), port_port);
                        data_client = new_client(port_address, port_port);
                        if (data_client < 0) {
                            err(1, "RETR: connect client error ");
                        }
                    // Mode not set
                    } else {
                        err(1, "RETR: transfer type no specified");
                        break;
                    }
                    
                    // Parse path
                    p = parse_path(buf);
                    // Invalid path
                    if (!p) {
                        err(1, "RETR, wrong param");
                        send_str(1, FTP_ERR_PARAM, "RETR");
                        break;
                    } else {
                        int st = send_path(data_client, p, restdata);
                        if (st >= 0) {
                            send_str(client, FTP_TRSF_OK);
                            restdata = 0;

                        /* added controlling permission error */
                        } else {
                            send_str(client, FTP_ERROR, st == -1 ? (access(p, F_OK)==0? "access denyed. Check Permission" : "file not exist") : "unknow error");
                        }
                    }
                    // Close data client
                    if (data_client >= 0) {
                        info(1, "RETR, closing data client ... %d", close(data_client));
                        data_client = -1;
                    }

                    // Close passive server connection
                    if (pasv_server >= 0) {
                        info(1, "RETR, closing passive server ... %d", close(pasv_server));
                        pasv_server = -1;
                    }
                    break;

                // Store data on server
                case STOR:
                    // Passive mode
                    if (trsf_type == TRSF_PASV) {
                        if (pasv_port > 1024 && pasv_port <= 65535 && pasv_server >= 0) {
                            // Ascii mode
                            if (datatype == TYPE_ASCII) {
                                send_str(client, FTP_ASCII, "STOR");
                            }
                            // Binary mode
                            else {
                                send_str(client, FTP_BIN, "STOR");
                            }
                            data_client = accept(pasv_server, (struct sockaddr *)&data_client_addr, &data_client_len);
                            if (data_client < 0) {
                                err(1, "STOR, accept data client error");
                                break;
                            }
                        } else {
                            err(1, "STOR, pasv server not ready ");
                        }
                    // Transfer mode
                    } else if (trsf_type == TRSF_PORT) {
                        // No server address and port
                        if (port_address == 0 || port_port == 0) {
                            err(1, "STOR, PORT mode, address and port not set before");
                            break;
                        }
                        // ascii type transfer
                        if (datatype == TYPE_ASCII) {
                            send_str(client, FTP_ASCII, "STOR");
                        }
                        // Binary transfer
                        else {
                            send_str(client, FTP_BIN, "STOR");
                        }
                        info(1, "STOR, PORT mode, try connecting %s %lu", n2a(port_address), port_port);
                        data_client = new_client(port_address, port_port);
                        if (data_client < 0) {
                            err(1, "STOR: connect client error ");
                        }
                    // Transfer type not specified
                    } else {
                        err(1, "STOR: transfer type no specified");
                        break;
                    }
                    // Parse path buffer
                    p = parse_path(buf);
                    // Invalid path
                    if (!p) {
                        err(1, "STOR, wrong param");
                        send_str(1, FTP_ERR_PARAM, "RETR");
                        break;
                    } else {
                        int st = recv_path(data_client, p, restdata);
                        if (st >= 0) {
                            send_str(client, FTP_TRSF_OK);
                            restdata = 0;
                        // Access permissions
                        } else {
                            send_str(client, FTP_ERROR, access(p, W_OK)!=0 ? "access denied. Check permission" : "unknow error");
                        }
                    }
                    // Close data client connection
                    if (data_client >= 0) {
                        info(1, "STOR, closing data client ... %d", close(data_client));
                        data_client = -1;
                    }
                    // Clsoe passive connection
                    if (pasv_server >= 0) {
                        info(1, "STOR, closing passive server ... %d", close(pasv_server));
                        pasv_server = -1;
                    }
                    break;

                // Change to parent directory
                case CDUP:
                    if (!chdir("..")) {
                        send_str(client, FTP_CDUP);
                    } else {
                        send_str(client, FTP_ERROR, "change to parent dir failed");
                    }
                    break;

                // Change working directory
                case CWD:
                    p = parse_path(buf);
                    // Check if supplied path is valid
                    if (!p) {
                        err(1, "CWD, wrong param");
                        send_str(1, FTP_ERR_PARAM, "CWD");
                        break;
                    }
                    // Change directory
                    info(1, "chdir \"%s\"", p);
                    if (!(chdir(p))) {
                        send_str(client, FTP_CWD);
                    } else {
                        err(1, "errno = %d, errstr is %s", errno, strerror(errno));
                        send_str(client, FTP_ERROR, "change dir failed");
                    }
                    break;
                
                // Change last modified time 
                case MDTM:
                
                // Return size of file
                case SIZE:
                    p = parse_path(buf);
                    // If path is wrong
                    if (!p) {
                        if (cmd == MDTM) {
                            err(1, "MDTM, wrong param");
                            send_str(client, FTP_ERR_PARAM, "MDTM");
                        } else {
                            err(1, "SIZE, wrong param");
                            send_str(client, FTP_ERR_PARAM, "SIZE");
                        }
                        break;
                    }
                    // Checks stats 
                    if (stat(p, &file_stat) == 0) {
                        // MDTM command
                        if (cmd == MDTM) {
                            char _buf[BUF_SIZE];
                            gmtime_r(&(file_stat.st_mtime), &mdtime);
                            strftime(_buf, sizeof(_buf), "%Y%m%d%H%M%S", &mdtime);
                            send_str(client, FTP_MDTM, _buf);
                        } 
                        // SIZE command
                        else {
                            send_str(client, FTP_SIZE, file_stat.st_size);
                        }
                    }
                    break;

                // Delete file
                case DELE:
                    // Check if path is valid
                    p = parse_path(buf);
                    if (!p) {
                        err(1, "DELE, param error");
                        send_str(client, FTP_ERR_PARAM, "DELE");
                    }
                    // Delete file
                    else {
                        if (remove(p) == 0) {
                            send_str(client, FTP_DELE);
                        } else {
                            send_str(client, FTP_ERROR, "delete failed, file not exist ?");
                        }
                    }
                    break;

                // Remove directory
                case RMD:
                    // Check if path is valid
                    p = parse_path(buf);
                    if (!p) {
                        err(1, "RMD, param error");
                        send_str(client, FTP_ERR_PARAM, "RMD");
                    } 
                    // Remove directory
                    else {
                        if (rmdir(p) == 0) {
                            send_str(client, FTP_DELE);
                        } else {
                            send_str(client, FTP_ERROR, "rmdir failed, dir not exist ?");
                        }
                    }
                    break;
                
                // Make directory
                case MKD:
                    // Check if path is valid
                    p = parse_path(buf);
                    if (!p) {
                        err(1, "MKD, param error");
                        send_str(client, FTP_ERR_PARAM, "MKD");
                    }
                    // Create directory
                    else {
                        if (mkdir(p, 0777) == 0) {
                            send_str(client, FTP_MKDIR);
                        } else {
                            send_str(client, FTP_ERROR, "mkdir failed, dir already exist ?");
                        }
                    }
                    break;

                // Rename file from, start renaming
                case RNFR:
                    p = parse_path(buf);
                    // Check if path is valid
                    if (!p) {
                        err(1, "RNFR param error");
                        send_str(client, FTP_ERR_PARAM, "RNFR");
                    }
                    // Else rename file
                    else {
                        strcpy(rnfr, p);
                        send_str(client, FTP_RNFR);
                    }
                    break;

                // REname file to, finish renaming
                case RNTO:
                    p = parse_path(buf);
                    // Check if path is valid
                    if (!p) {
                        err(1, "RNTO param error");
                        send_str(client, FTP_ERR_PARAM, "RNTO");
                    }
                    // Send finish rename
                    else {
                        if (rename(rnfr, p) == 0) {
                            send_str(client, FTP_RNTO);
                        } else {
                            send_str(client, FTP_ERROR, "rnto error, please check param");
                        }
                    }
                    break;

                // Default
                default:
                    send_str(client, FTP_CMDNOIM);
                    break;
            }
        }

        // Free p
        if (p) {
            free(p);
            p = NULL;
        }

        // If not running, break loop
        if (!running) break;
    }

    // Exit session
    info(1, "exiting session ...");
    // Close client
    int st = close(client);
    info(1, "clent closed , status %d", st);
    client = -1;

    // Close connections
    if (data_client > 0) {
        info(1, "data client closed, status %d", close(data_client));
    }
    if (pasv_server > 0) {
        info(1, "pasv server closed, status %d", close(pasv_server));
    }
}

// Main
int main(int argc, char *argv[]){
    int port = LISTEN_PORT;

    // Get uid for login info
    if(getuid() != 0){
        printf("You need a root permission. Try \"sudo %s\" (or \"su\" as root).\nQuit program....\n",argv[0]);
        exit(0);
    }

    // If port is supplied
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    // Handle signals
    signal(SIGCHLD, SIG_IGN);   // ignore child termination signal
    signal(SIGINT, ouch);       // catch Ctrl-C 
    signal(SIGTERM, ouch);

    // Create new server
    server = new_server(LISTEN_ADDR, port, MAX_CONNECTIONS);
    if (server < 0) {
        err(0, "can not create server, return code is %d, socket already in use", server);
        exit(1);
    }
    running = 1;

    // Loop for listening to client requests
    struct sockaddr_in client_addr;
    while (running) {
        // Accept client request
        uint32_t l = sizeof(client_addr);
        client = accept(server, (struct sockaddr *)&client_addr, &l);

        // Exit if client exits
        if (!running) break;
        if (client < 0) {
            err(0, "accept client error: %d", client);
            exit(2);
        }
        info(0, "client connected: %s", inet_ntoa(client_addr.sin_addr));
        
        // Fork server to service client
        forkpid = fork();
        // If fork fails
        if (forkpid == -1) {
            err(0, "fork server error");
        } 
        // Child process
        else if (forkpid == 0) {      // child
            server = -1;        // avoid killing server on Ctrl-C
            info(0, "new ftp session");
            // Handle client
            handle_session(client);
            exit(0);
        } 
        // Main thread
        else if (forkpid > 0) {
            client = -1;
        }
    }
    
    // Exit
    info(0, "exit ftpd");
    return 0;
}


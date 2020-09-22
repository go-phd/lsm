
#ifndef _PHDLSM_H
#define _PHDLSM_H

#define PHDLSM_MAX_NUM	8
#define PHDLSM_FILE_PATH_MAX_LEN	128
#define PHDLSM_NAME_MAX_LEN PHDLSM_FILE_PATH_MAX_LEN

enum phdlsm_type_e {
	PHDLSM_DISK = 0,
	PHDLSM_MAGR = 1,
	PHDLSM_MAX = 2
};

struct phdlsm_pid_record_s {
	int pid;									// 允许访问文件的进程pid
	char service_name[PHDLSM_NAME_MAX_LEN];		// 对应的进程名
};


struct phdlsm_file_ct_s {
	struct phdlsm_pid_record_s pid_record[PHDLSM_MAX_NUM];		// 记录允许访问文件的进程
	char file_name[PHDLSM_MAX_NUM][PHDLSM_FILE_PATH_MAX_LEN];	// 记录需要控制访问的文件列表
};

struct phdlsm_ct_s {
	struct phdlsm_file_ct_s disk;
	struct phdlsm_file_ct_s magr;
};

int add_ctrl_current_pid(enum phdlsm_type_e type, char *service_name);
int add_ctrl_file(enum phdlsm_type_e type, char *filename);


#endif



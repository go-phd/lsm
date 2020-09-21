
#ifndef _PHDLSM_H
#define _PHDLSM_H

#define PHDLSM_MAX_NUM	8
#define PHDLSM_FILE_PATH_MAX_LEN	128

enum phdlsm_type_e {
	PHDLSM_DISK = 0,
	PHDLSM_MAGR = 1,
	PHDLSM_MAX = 2
};

struct phdlsm_file_ct_s {
	int pid[PHDLSM_MAX_NUM];							// 允许访问文件的进程pid
	char file_name[PHDLSM_MAX_NUM][PHDLSM_FILE_PATH_MAX_LEN];	// 控制访问的文件列表
};

struct phdlsm_ct_s {
	struct phdlsm_file_ct_s disk;
	struct phdlsm_file_ct_s magr;
};

int add_ctrl_current_pid(enum phdlsm_type_e type);
int add_ctrl_file(enum phdlsm_type_e type, char *filename);


#endif



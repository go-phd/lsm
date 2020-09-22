#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>

#include <phd/phdlsm.h>
#include <phd/kbox.h>


struct phdlsm_ct_s g_ct = {};

int add_ctrl_current_pid(enum phdlsm_type_e type, char *service_name) {
	int i = 0;
	size_t real_len = 0;
	struct phdlsm_file_ct_s *fct = NULL;

	if (!service_name) {
		KBOX_LOG(KLOG_ERROR,  "service_name is NULL\n");
		return -EINVAL;
	}

	real_len = strlen(service_name);

	if (real_len == 0 || real_len >= PHDLSM_NAME_MAX_LEN) {
		KBOX_LOG(KLOG_ERROR,  "service_name length is invalid\n");
		return -EINVAL;
	}

	switch (type) {
		case PHDLSM_DISK:
			fct = &g_ct.disk;
			break;
		case PHDLSM_MAGR:
			fct = &g_ct.magr;
			break;
		default:
			printk(KERN_ALERT "type error, type = 0x%x\n", type);
			return -EINVAL;
	}

	for (i = 0; i < PHDLSM_MAX_NUM; i++) {
		if (!strcmp(service_name, fct->pid_record[i].service_name)) {
			fct->pid_record[i].pid = task_pid_nr(current);
			return 0;
		}
	}

	for (i = 0; i < PHDLSM_MAX_NUM; i++) {
		if (fct->pid_record[i].pid == 0)) {
			strcpy(fct->pid_record[i].service_name, service_name);
			fct->pid_record[i].pid = task_pid_nr(current);
			return 0;
		}
	}

	KBOX_LOG(KLOG_ERROR, "no space\n");
	return -ENOSPC;
}
EXPORT_SYMBOL(add_ctrl_current_pid);

int add_ctrl_file(enum phdlsm_type_e type, char *filename) {
	int i = 0;
	size_t real_len = 0;
	struct phdlsm_file_ct_s *fct = NULL;

	if (!filename) {
		KBOX_LOG(KLOG_ERROR,  "filename is NULL\n");
		return -EINVAL;
	}

	real_len = strlen(filename);

	if (real_len == 0 || real_len >= PHDLSM_FILE_PATH_MAX_LEN) {
		KBOX_LOG(KLOG_ERROR,  "filename length is invalid\n");
		return -EINVAL;
	}

	switch (type) {
		case PHDLSM_DISK:
			fct = &g_ct.disk;
			break;
		case PHDLSM_MAGR:
			fct = &g_ct.magr;
			break;
		default:
			KBOX_LOG(KLOG_ERROR,  "type error, type = 0x%x\n", type);
			return -EINVAL;
	}

	for (i = 0; i < PHDLSM_MAX_NUM; i++) {
		if (strlen(fct->file_name[i]) == 0) {
			strcpy(fct->file_name[i], filename);
			return 0;
		}
	}

	KBOX_LOG(KLOG_ERROR, "no space\n");
	return -ENOSPC;
}
EXPORT_SYMBOL(add_ctrl_file);


static int phd_file_ctrl(struct dentry *dentry, struct phdlsm_file_ct_s *fct)
{
	int i = 0;
	char cur_path[PHDLSM_FILE_PATH_MAX_LEN] = {};
	char *path = NULL;
	int pid = task_pid_nr(current);

	KBOX_LOG(KLOG_DEBUG, "phd_file_ctrl, current pid = 0x%x\n", pid);

	path = dentry_path_raw(dentry, cur_path, PHDLSM_FILE_PATH_MAX_LEN);
	if (IS_ERR(path)) {
		KBOX_LOG(KLOG_ERROR, "dentry_path_raw fail, ret =  0x%lx\n", PTR_ERR(path));
		return 0;
	}

	// 遍历比较
	for (i = 0; i < PHDLSM_MAX_NUM; i++) {
		char *file_name = fct->file_name;
		if (!strncmp(path, file_name, strlen(file_name))) {
			int j = 0;

			for (j = 0; j < PHDLSM_MAX_NUM; j++) {
				if (fct->pid_record.pid[j] > 0 && pid == fct->pid_record.pid[j]) {
					
					// 授权访问
					KBOX_LOG(KLOG_DEBUG, "%s allowed to access %s\n", fct->pid_record.service_name, path);
					return 0;
				}
			}

			// 无权操作
			KBOX_LOG(KLOG_ERROR, "not allowed to access\n";
			return -EPERM;
		}
	}

	// 无需控制
	return 0;
}


static int phd_file_open(struct file *filp)
{
	return phd_file_ctrl(filp->f_path.dentry, &g_ct.disk);
}

static int phd_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return phd_file_ctrl(dentry, &g_ct.magr);
}


static struct security_hook_list pdh_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_open, phd_file_open),
	LSM_HOOK_INIT(inode_unlink, phd_inode_unlink),
};


static int __init phdlsm_init(void)
{
	int ret = 0;

	memset(&g_ct, 0, sizeof(struct phdlsm_ct_s));

	// /dev/sda 块设备文件默认不允许公共访问
	ret = add_ctrl_file(PHDLSM_DISK, "/dev/sda");
	RETURN_VAL_DO_INFO_IF_FAIL(!ret, ret,
			KBOX_LOG(KLOG_ERROR, "add_ctrl_file failed! ret = %d\n", ret););

	// register ourselves with the security framework
	security_add_hooks(pdh_hooks, ARRAY_SIZE(pdh_hooks), "pdh");
	
	KBOX_LOG(KLOG_DEBUG,  "phd lsm initialized\n");

	return 0;
}

security_initcall(phdlsm_init);


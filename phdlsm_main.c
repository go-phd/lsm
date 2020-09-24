
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
		case PHDLSM_OPEN:
			fct = &g_ct.open;
			break;
		case PHDLSM_DEL:
			fct = &g_ct.del;
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
		if (fct->pid_record[i].pid == 0) {
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
		case PHDLSM_OPEN:
			fct = &g_ct.open;
			break;
		case PHDLSM_DEL:
			fct = &g_ct.del;
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

	path = dentry_path_raw(dentry, cur_path, PHDLSM_FILE_PATH_MAX_LEN);
	if (IS_ERR(path)) {
		KBOX_LOG(KLOG_ERROR, "dentry_path_raw fail, ret =  0x%lx\n", PTR_ERR(path));
		return 0;
	}

	//KBOX_LOG(KLOG_DEBUG, "phd_file_ctrl, current pid = 0x%x, path = %s\n", pid, path);

	// 遍历比较
	for (i = 0; i < PHDLSM_MAX_NUM; i++) {
		char *file_name = fct->file_name[i];
		int len = strlen(file_name);
		if (len > 0 && !strncmp(path, file_name, len)) {
			int j = 0;

			//KBOX_LOG(KLOG_DEBUG, "file_name = %s\n", file_name);

			for (j = 0; j < PHDLSM_MAX_NUM; j++) {
				if (fct->pid_record[j].pid > 0 && pid == fct->pid_record[j].pid) {
					
					// 授权访问
					printk(KERN_INFO "%s allowed to access %s\n", fct->pid_record[j].service_name, path);
					return 0;
				}
			}

			// 无权操作
			printk(KERN_ALERT "not allowed to access %s\n", file_name);
			//return 0;
			return -EPERM;
		}
	}

	// 无需控制
	return 0;
}


static int phd_file_open(struct file *filp, const struct cred *cred)
{
	return phd_file_ctrl(filp->f_path.dentry, &g_ct.open);
}

static int phd_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return phd_file_ctrl(dentry, &g_ct.del);
}


static struct security_hook_list pdh_hooks[] = {
	LSM_HOOK_INIT(file_open, phd_file_open),
	LSM_HOOK_INIT(inode_unlink, phd_inode_unlink),
};


static int __init phdlsm_init(void)
{
	int ret = 0;

	memset(&g_ct, 0, sizeof(struct phdlsm_ct_s));

	// /dev/sda 块设备文件默认不允许公共访问
	ret = add_ctrl_file(PHDLSM_OPEN, "/sda");
	RETURN_VAL_DO_INFO_IF_FAIL(!ret, ret,
			KBOX_LOG(KLOG_ERROR, "add_ctrl_file failed! ret = %d\n", ret););

	// register ourselves with the security framework
	security_add_hooks(pdh_hooks, ARRAY_SIZE(pdh_hooks));
	
	printk(KERN_INFO "PHD LSM initialized\n");

	return 0;
}

security_initcall(phdlsm_init);


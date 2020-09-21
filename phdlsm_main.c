#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>

#include "phdlsm.h"

struct phdlsm_ct_s g_ct = {};

int add_ctrl_current_pid(enum phdlsm_type_e type) {
	int i = 0;
	struct phdlsm_file_ct_s *fct = NULL;

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
		if (fct->pid[i] == 0) {
			fct->pid[i] = task_pid_nr(current);
			return 0;
		}
	}

	return -ENOSPC;
}
EXPORT_SYMBOL(add_ctrl_current_pid);

int add_ctrl_file(enum phdlsm_type_e type, char *filename) {
	int i = 0;
	size_t real_len = 0;
	struct phdlsm_file_ct_s *fct = NULL;

	if (!filename) {
		return -EINVAL;
	}

	real_len = strlen(filename);

	if (real_len == 0 || real_len >= PHDLSM_FILE_PATH_MAX_LEN) {
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
		if (strlen(fct->file_name[i]) == 0) {
			strcpy(fct->file_name[i], filename);
			return 0;
		}
	}

	return -ENOSPC;
}
EXPORT_SYMBOL(add_ctrl_file);


static int phd_file_ctrl(struct dentry *dentry, struct phdlsm_file_ct_s *fct)
{
	int i = 0;
	char cur_path[PHDLSM_FILE_PATH_MAX_LEN] = {};
	char *path = NULL;
	int pid = task_pid_nr(current);

	printk(KERN_ALERT "phd_file_ctrl, current pid = 0x%x\n", pid);

	path = dentry_path_raw(dentry, cur_path, PHDLSM_FILE_PATH_MAX_LEN);
	if (IS_ERR(path)) {
		printk(KERN_ALERT "dentry_path_raw fail, ret =  0x%lx\n", PTR_ERR(path));
		return 0;
	}

	// 遍历比较
	for (i = 0; i < PHDLSM_MAX_NUM; i++) {
		if (!strncmp(path, fct->file_name[i], strlen(path))) {
			int j = 0;

			for (j = 0; j < PHDLSM_MAX_NUM; j++) {
				if (fct->pid[j] > 0 && pid == fct->pid[j]) {

					// 授权访问
					return 0;
				}
			}

			// 无权操作
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
	if (!security_module_enable("phd"))
		return 0;

	memset(&g_ct, 0, sizeof(struct phdlsm_ct_s));

	// register ourselves with the security framework
	security_add_hooks(pdh_hooks, ARRAY_SIZE(pdh_hooks), "pdh");
	printk(KERN_INFO "PHD initialized\n");

	return 0;
}

security_initcall(phdlsm_init);


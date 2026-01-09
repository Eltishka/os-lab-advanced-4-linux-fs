#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

static unsigned int mask = 1;
#define MODULE_NAME "vtfs"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

struct dentry* vtfs_mount(
    struct file_system_type* fs_type, int flags, const char* token, void* data
);

struct dentry* vtfs_lookup(
    struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag
);

int vtfs_unlink(struct inode* parent_inode, struct dentry* child_dentry);
int vtfs_create(
    struct mnt_idmap* idmap,
    struct inode* parent_inode,
    struct dentry* child_dentry,
    umode_t mode,
    bool b
);

struct dentry* mount_nodev(
    struct file_system_type* fs_type,
    int flags,
    void* data,
    int (*fill_super)(struct super_block*, void*, int)
);
int vtfs_fill_super(struct super_block* sb, void* data, int silent);
struct inode* vtfs_get_inode(
    struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino
);
int vtfs_permission(struct mnt_idmap* idmap, struct inode* inode, int mask);
int vtfs_iterate(struct file* filp, struct dir_context* ctx);
void vtfs_kill_sb(struct super_block* sb);

struct file_system_type vtfs_fs_type = {
    .name = "vtfs",
    .mount = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .permission = vtfs_permission,
    .create = vtfs_create,
    .unlink = vtfs_unlink
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct dentry* vtfs_mount(
    struct file_system_type* fs_type, int flags, const char* token, void* data
) {
  struct dentry* ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
  if (ret == NULL) {
    printk(KERN_ERR "Can't mount file system");
  } else {
    printk(KERN_INFO "Mounted successfuly");
  }
  return ret;
}

struct dentry* vtfs_lookup(
    struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag
) {
  ino_t root = parent_inode->i_ino;
  const char* name = child_dentry->d_name.name;
  if (root == 100 && !strcmp(name, "test.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG, 101);
    d_add(child_dentry, inode);
  } else if (root == 100 && !strcmp(name, "new_file.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG, 102);
    d_add(child_dentry, inode);
  } else if (root == 100 && !strcmp(name, "dir")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFDIR, 200);
    d_add(child_dentry, inode);
  }
  return NULL;
}

int vtfs_create(
    struct mnt_idmap* idmap,
    struct inode* parent_inode,
    struct dentry* child_dentry,
    umode_t mode,
    bool b
) {
  ino_t root = parent_inode->i_ino;
  const char* name = child_dentry->d_name.name;
  if (root == 100 && !strcmp(name, "test.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG | S_IRWXUGO, 101);
    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = NULL;
    d_add(child_dentry, inode);
    mask |= 1;
  } else if (root == 100 && !strcmp(name, "new_file.txt")) {
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFREG | S_IRWXUGO, 102);
    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = NULL;
    d_add(child_dentry, inode);
    mask |= 2;
  }
  return 0;
}

int vtfs_unlink(struct inode* parent_inode, struct dentry* child_dentry) {
  const char* name = child_dentry->d_name.name;
  ino_t root = parent_inode->i_ino;
  if (root == 100 && !strcmp(name, "test.txt")) {
    mask &= ~1;
  } else if (root == 100 && !strcmp(name, "new_file.txt")) {
    mask &= ~2;
  }
  return 0;
}

int vtfs_fill_super(struct super_block* sb, void* data, int silent) {
  struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR | 0777, 100);
  sb->s_root = d_make_root(inode);
  if (sb->s_root == NULL) {
    return -ENOMEM;
  }

  inode->i_op = &vtfs_inode_ops;
  printk(KERN_INFO "return 0\n");
  return 0;
}

struct inode* vtfs_get_inode(
    struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino
) {
  struct inode* inode = new_inode(sb);
  if (!inode)
    return NULL;

  inode->i_ino = i_ino;
  inode->i_mode = (mode & S_IFMT) | S_IRWXUGO;
  inode_init_owner(&nop_mnt_idmap, inode, dir, mode);

  if (S_ISDIR(mode)) {
    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;

    set_nlink(inode, 2);
  }

  return inode;
}

int vtfs_iterate(struct file* filp, struct dir_context* ctx) {
  struct dentry* dentry = filp->f_path.dentry;
  struct inode* inode = dentry->d_inode;

  if (inode->i_ino != 100) {
    return 0;
  }

  if (ctx->pos == 0) {
    if (!dir_emit(ctx, ".", 1, inode->i_ino, DT_DIR))
      return 0;
    ctx->pos++;
  }

  if (ctx->pos == 1) {
    struct inode* parent_inode = dentry->d_parent->d_inode;
    if (!dir_emit(ctx, "..", 2, parent_inode ? parent_inode->i_ino : 2, DT_DIR))
      return 0;
    ctx->pos++;
  }

  if (ctx->pos == 2) {
    if (mask & 1) {
      if (!dir_emit(ctx, "test.txt", 8, 101, DT_REG))
        return 0;
    }
    ctx->pos++;
  }

  if (ctx->pos == 3) {
    if (!dir_emit(ctx, "dir", 3, 200, DT_DIR))
      return 0;
    ctx->pos++;
  }

  if (ctx->pos == 4) {
    if (mask & 2) {
      if (!dir_emit(ctx, "new_file.txt", 12, 102, DT_REG))
        return 0;
    }
    ctx->pos++;
  }

  return 0;
}

void vtfs_kill_sb(struct super_block* sb) {
  printk(KERN_INFO "vtfs super block is destroyed. Unmount successfully.\n");
}

int vtfs_permission(struct mnt_idmap* idmap, struct inode* inode, int mask) {
  return 0;
}

static int __init vtfs_init(void) {
  int ret = register_filesystem(&vtfs_fs_type);
  if (ret) {
    printk(KERN_ERR "[" MODULE_NAME "]: Failed to register filesystem: %d\n", ret);
    return ret;
  }
  LOG("VTFS joined the kernel\n");
  return 0;
}

static void __exit vtfs_exit(void) {
  unregister_filesystem(&vtfs_fs_type);
  LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rwlock.h>

#define MODULE_NAME "vtfs"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)
#define VTFS_MAX_NAME_LEN 256
#define VTFS_MAX_DATA_SIZE 4096


struct vtfs_inode_data {
    ino_t ino;
    umode_t mode;
    char name[VTFS_MAX_NAME_LEN];
    ino_t parent_ino; 
    
    union {
        struct {
            char *data;
            size_t size;
        } file;
    };
    
    struct list_head list;
};

struct vtfs_super_info {
    struct list_head inodes;
    rwlock_t lock;
};

static struct vtfs_super_info vtfs_sb_info;


static struct vtfs_inode_data *vtfs_find_inode(ino_t ino)
{
    struct vtfs_inode_data *entry;
    
    read_lock(&vtfs_sb_info.lock);
    list_for_each_entry(entry, &vtfs_sb_info.inodes, list) {
        if (entry->ino == ino) {
            read_unlock(&vtfs_sb_info.lock);
            return entry;
        }
    }
    read_unlock(&vtfs_sb_info.lock);
    return NULL;
}

static struct vtfs_inode_data *vtfs_find_child(ino_t parent_ino, const char *name)
{
    struct vtfs_inode_data *entry;
    
    read_lock(&vtfs_sb_info.lock);
    list_for_each_entry(entry, &vtfs_sb_info.inodes, list) {
        if (entry->parent_ino == parent_ino && 
            strcmp(entry->name, name) == 0) {
            read_unlock(&vtfs_sb_info.lock);
            return entry;
        }
    }
    read_unlock(&vtfs_sb_info.lock);
    return NULL;
}

static struct vtfs_inode_data *vtfs_create_inode(ino_t ino, umode_t mode, 
                                                  const char *name, ino_t parent_ino)
{
    struct vtfs_inode_data *inode_data;
    
    inode_data = kzalloc(sizeof(*inode_data), GFP_KERNEL);
    if (!inode_data)
        return NULL;
    
    inode_data->ino = ino;
    inode_data->mode = mode;
    inode_data->parent_ino = parent_ino;
    strncpy(inode_data->name, name, VTFS_MAX_NAME_LEN - 1);
    inode_data->name[VTFS_MAX_NAME_LEN - 1] = '\0';
    
    if (S_ISREG(mode)) {
        inode_data->file.data = NULL;
        inode_data->file.size = 0;
    }
    
    write_lock(&vtfs_sb_info.lock);
    list_add_tail(&inode_data->list, &vtfs_sb_info.inodes);
    write_unlock(&vtfs_sb_info.lock);
    
    return inode_data;
}

static int vtfs_remove_inode(ino_t ino)
{
    struct vtfs_inode_data *inode_data;
    
    inode_data = vtfs_find_inode(ino);
    if (!inode_data)
        return -ENOENT;
    
    write_lock(&vtfs_sb_info.lock);
    list_del(&inode_data->list);
    write_unlock(&vtfs_sb_info.lock);
    
    if (S_ISREG(inode_data->mode) && inode_data->file.data)
        kfree(inode_data->file.data);
    
    kfree(inode_data);
    return 0;
}

static int vtfs_remove_child(ino_t parent_ino, const char *name)
{
    struct vtfs_inode_data *child;
    
    child = vtfs_find_child(parent_ino, name);
    if (!child)
        return -ENOENT;
    
    return vtfs_remove_inode(child->ino);
}


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
    const char* name = child_dentry->d_name.name;
    struct vtfs_inode_data *inode_data;
    
    inode_data = vtfs_find_child(parent_inode->i_ino, name);
    if (!inode_data)
        return NULL;
    
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, 
                                        inode_data->mode, inode_data->ino);
    if (inode) {
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
    const char* name = child_dentry->d_name.name;
    ino_t ino;
    
    if (vtfs_find_child(parent_inode->i_ino, name))
        return -EEXIST;
    
    static ino_t next_ino = 1000;
    ino = next_ino++;
    
    struct vtfs_inode_data *inode_data = vtfs_create_inode(ino, mode, name, 
                                                           parent_inode->i_ino);
    if (!inode_data)
        return -ENOMEM;
    
    struct inode* inode = vtfs_get_inode(parent_inode->i_sb, NULL, mode, ino);
    if (!inode)
        return -ENOMEM;
    
    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = NULL;
    d_add(child_dentry, inode);
    
    return 0;
}

int vtfs_unlink(struct inode* parent_inode, struct dentry* child_dentry) {
    const char* name = child_dentry->d_name.name;
    
    return vtfs_remove_child(parent_inode->i_ino, name);
}

int vtfs_fill_super(struct super_block* sb, void* data, int silent) {
    INIT_LIST_HEAD(&vtfs_sb_info.inodes);
    rwlock_init(&vtfs_sb_info.lock);
    
    struct vtfs_inode_data *root_data = vtfs_create_inode(100, S_IFDIR | 0777, "", 0);
    if (!root_data)
        return -ENOMEM;
    
    struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR | 0777, 100);
    sb->s_root = d_make_root(inode);
    if (sb->s_root == NULL) {
        return -ENOMEM;
    }

    inode->i_op = &vtfs_inode_ops;
    return 0;
}

struct inode* vtfs_get_inode(
    struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino
) {
    struct inode* inode = new_inode(sb);
    if (!inode)
        return NULL;

    inode->i_ino = i_ino;
    inode->i_mode = mode;
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
    struct vtfs_inode_data *entry;
    int skip_count, current_pos;
    
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
    
    skip_count = ctx->pos - 2;
    current_pos = 0;
    
    read_lock(&vtfs_sb_info.lock);
    
    list_for_each_entry(entry, &vtfs_sb_info.inodes, list) {
        if (entry->parent_ino != inode->i_ino)
            continue;
            
        if (current_pos < skip_count) {
            current_pos++;
            continue;
        }
        
        unsigned char type;
        if (S_ISDIR(entry->mode))
            type = DT_DIR;
        else if (S_ISREG(entry->mode))
            type = DT_REG;
        else
            type = DT_UNKNOWN;
            
        if (!dir_emit(ctx, entry->name, strlen(entry->name), entry->ino, type)) {
            read_unlock(&vtfs_sb_info.lock);
            return 0;
        }
        
        ctx->pos++;
        current_pos++;
    }
    
    read_unlock(&vtfs_sb_info.lock);
    
    return 0;
}

void vtfs_kill_sb(struct super_block* sb) {
    struct vtfs_inode_data *entry, *tmp;
    
    write_lock(&vtfs_sb_info.lock);
    list_for_each_entry_safe(entry, tmp, &vtfs_sb_info.inodes, list) {
        list_del(&entry->list);
        if (S_ISREG(entry->mode) && entry->file.data)
            kfree(entry->file.data);
        kfree(entry);
    }
    write_unlock(&vtfs_sb_info.lock);
    
    printk(KERN_INFO "[" MODULE_NAME "]: Super block destroyed. Unmount successful.\n");
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
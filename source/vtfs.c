#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rwlock.h>
#include <linux/base64.h>
#include "http.h"

#define MODULE_NAME "vtfs"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)
#define VTFS_MAX_NAME_LEN 256
#define ROOT_INO 1000
#define HTTP_BUFFER_SIZE 4096
#define LARGE_HTTP_BUFFER_SIZE 4096000
#define INO_BUFFER_SIZE 64

#define HTTP_METHOD_GET "GET"
#define HTTP_METHOD_POST "POST"
#define HTTP_METHOD_PUT "PUT"
#define HTTP_METHOD_DELETE "DELETE"

#define ENDPOINT_INODE_BY_INO "/inodeByIno"
#define ENDPOINT_INODE_BY_PARENT "/inodeByParentInoAndName"
#define ENDPOINT_CREATE_INODE "/createInode"
#define ENDPOINT_DELETE_INODE "/deleteInode"
#define ENDPOINT_GET_ALL "/getAll"
#define ENDPOINT_FILE_BY_INO "/fileByIno"
#define ENDPOINT_FILES "/files"
#define ENDPOINT_GET_MAX_INO "/getMaxIno"

#define JSON_FIELD_INO "\"ino\":"
#define JSON_FIELD_MODE "\"mode\":"
#define JSON_FIELD_NAME "\"name\":\""
#define JSON_FIELD_PARENT_INO "\"parentIno\":"
#define JSON_FIELD_SIZE "\"size\":"
#define JSON_FIELD_DATA "\"data\":\""

struct file_data {
  char *data;
  size_t size;
};

struct vtfs_inode_data {
    ino_t ino;
    umode_t mode;
    char name[VTFS_MAX_NAME_LEN];
    ino_t parent_ino; 
    struct list_head list;
};

static int parse_json_file_data(const char *json, struct file_data *fdata)
{
    const char *data_start = NULL;
    const char *data_end = NULL;
    const char *size_start = NULL;
    char *decoded_data = NULL;
    size_t encoded_len = 0;
    size_t decoded_len = 0;
    long size = 0;
    char *size_endptr = NULL;
    int ret = 0;

    if (!json || !fdata) {
        return -EINVAL;
    }

    fdata->data = NULL;
    fdata->size = 0;

    size_start = strstr(json, JSON_FIELD_SIZE);
    if (!size_start) {
        return 0;
    }
    size_start += strlen(JSON_FIELD_SIZE); 
    size = simple_strtol(size_start, &size_endptr, 10);
    fdata->size = (size_t)size;
    data_start = strstr(json, JSON_FIELD_DATA);
    data_start += strlen(JSON_FIELD_DATA); 
    data_end = strchr(data_start, '\"');

    encoded_len = data_end - data_start;
    decoded_data = kmalloc(fdata->size, GFP_KERNEL);
    if (!decoded_data) {
        return -ENOMEM;
    }

    decoded_len = base64_decode(data_start, encoded_len, decoded_data);
    fdata->data = decoded_data;

    return 0;
}


static int parse_json_inode(const char *json, struct vtfs_inode_data *inode) {
    char *ptr = (char *)json;
    char *ino_start, *mode_start, *name_start, *parent_start, *name_end;
    size_t name_len;
    
    ino_start = strstr(ptr, JSON_FIELD_INO);
    if (!ino_start) return -EINVAL;
    ino_start += strlen(JSON_FIELD_INO); 
    
    mode_start = strstr(ptr, JSON_FIELD_MODE);
    if (!mode_start) return -EINVAL;
    mode_start += strlen(JSON_FIELD_MODE); 
    
    name_start = strstr(ptr, JSON_FIELD_NAME);
    if (!name_start) return -EINVAL;
    name_start += strlen(JSON_FIELD_NAME); 
    
    parent_start = strstr(ptr, JSON_FIELD_PARENT_INO);
    if (!parent_start) return -EINVAL;
    parent_start += strlen(JSON_FIELD_PARENT_INO);
    
    inode->ino = simple_strtoul(ino_start, NULL, 10);
    inode->mode = simple_strtoul(mode_start, NULL, 10);
    inode->parent_ino = simple_strtoul(parent_start, NULL, 10);
    
    name_end = strchr(name_start, '"');
    if (!name_end) return -EINVAL;
    
    name_len = name_end - name_start;
    if (name_len >= VTFS_MAX_NAME_LEN)
        name_len = VTFS_MAX_NAME_LEN - 1;
    
    strncpy(inode->name, name_start, name_len);
    inode->name[name_len] = '\0';
    return 0;
}

static void free_inodes_list(struct list_head *inodes_list)
{
    struct vtfs_inode_data *entry, *tmp;
    
    list_for_each_entry_safe(entry, tmp, inodes_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

static int parse_inode_array(const char *json, struct list_head *inodes_list) {
    char *ptr = (char *)json;
    
    ptr = strchr(ptr, '[');
    if (!ptr) return -EINVAL;
    ptr++; 
    
    while (*ptr && *ptr != ']') {
        while (*ptr && (*ptr == ' ' || *ptr == '\n' || *ptr == '\t' || *ptr == ','))
            ptr++;
        
        if (*ptr == ']') break;
        if (*ptr != '{') return -EINVAL;
        
        struct vtfs_inode_data *inode = kzalloc(sizeof(*inode), GFP_KERNEL);
        if (!inode) {
            free_inodes_list(inodes_list);
            return -ENOMEM;
        }
        
        INIT_LIST_HEAD(&inode->list); 
        
        int ret = parse_json_inode(ptr, inode);
        if (ret) {
            kfree(inode);
            free_inodes_list(inodes_list);
            return ret;
        }
        
        list_add_tail(&inode->list, inodes_list);
        
        ptr = strchr(ptr, '}');
        if (!ptr) break;
        ptr++;
    }
    
    return 0;
}

static struct vtfs_inode_data *vtfs_find_inode(ino_t ino)
{
    struct vtfs_inode_data *entry = kzalloc(sizeof(struct vtfs_inode_data), GFP_KERNEL);
    char *response_buffer = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL); 
    char *ino_str;
    int64_t ret;
    
    if (!entry || !response_buffer) {
        kfree(entry);
        kfree(response_buffer);
        return NULL;
    }
    
    ino_str = kasprintf(GFP_KERNEL, "%lu", ino);
    if (!ino_str) {
        kfree(entry);
        kfree(response_buffer);
        return NULL;
    }
    
    ret = vtfs_http_call(ENDPOINT_INODE_BY_INO, HTTP_METHOD_GET, response_buffer, HTTP_BUFFER_SIZE, 1, "ino", ino_str);
    kfree(ino_str);
    
    if(ret < 0) {
        kfree(entry);
        kfree(response_buffer);
        return NULL;
    }
    
    if (parse_json_inode(response_buffer, entry) < 0) {
        kfree(entry);
        kfree(response_buffer);
        return NULL;
    }
    
    kfree(response_buffer);
    return entry;
}

static struct vtfs_inode_data *vtfs_find_child(ino_t parent_ino, const char *name)
{
    struct vtfs_inode_data *entry = kzalloc(sizeof(struct vtfs_inode_data), GFP_KERNEL);
    char *response_buffer = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    char *parent_ino_str;
    int64_t ret;
    
    if (!entry || !response_buffer) {
        kfree(entry);
        kfree(response_buffer);
        return NULL;
    }
    
    parent_ino_str = kasprintf(GFP_KERNEL, "%lu", parent_ino);
    if (!parent_ino_str) {
        kfree(entry);
        kfree(response_buffer);
        return NULL;
    }
    
    ret = vtfs_http_call(ENDPOINT_INODE_BY_PARENT, HTTP_METHOD_GET, response_buffer, HTTP_BUFFER_SIZE, 2, 
                        "parentIno", parent_ino_str, "name", name);
    kfree(parent_ino_str);
    
    if(ret < 0 || parse_json_inode(response_buffer, entry) < 0) {
        kfree(entry);
        kfree(response_buffer);
        return NULL;
    }
    
    kfree(response_buffer);
    return entry;
}

static struct vtfs_inode_data *vtfs_create_inode(ino_t ino, umode_t mode, 
                                                  const char *name, ino_t parent_ino)
{
    struct vtfs_inode_data *inode_data;
    char *response_buffer;
    char *ino_str, *mode_str, *parent_ino_str;
    int64_t ret;
    
    inode_data = kzalloc(sizeof(*inode_data), GFP_KERNEL);
    if (!inode_data)
        return NULL;
    
    inode_data->ino = ino;
    inode_data->mode = mode;
    inode_data->parent_ino = parent_ino;
    strncpy(inode_data->name, name, VTFS_MAX_NAME_LEN - 1);
    inode_data->name[VTFS_MAX_NAME_LEN - 1] = '\0';
    
    response_buffer = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer) {
        kfree(inode_data);
        return NULL;
    }
    
    ino_str = kasprintf(GFP_KERNEL, "%lu", ino);
    mode_str = kasprintf(GFP_KERNEL, "%u", mode);
    parent_ino_str = kasprintf(GFP_KERNEL, "%lu", parent_ino);
    
    if (!ino_str || !mode_str || !parent_ino_str) {
        kfree(ino_str);
        kfree(mode_str);
        kfree(parent_ino_str);
        kfree(response_buffer);
        kfree(inode_data);
        return NULL;
    }
    
    ret = vtfs_http_call(ENDPOINT_CREATE_INODE, HTTP_METHOD_GET, response_buffer, HTTP_BUFFER_SIZE, 4, 
                     "ino", ino_str,
                     "mode", mode_str,
                     "name", name,
                     "parentIno", parent_ino_str);
    
    kfree(ino_str);
    kfree(mode_str);
    kfree(parent_ino_str);
    kfree(response_buffer);
    
    if (ret < 0) {
        kfree(inode_data);
        return NULL;
    }
    
    return inode_data;
}

static int vtfs_remove_inode(ino_t ino)
{
    struct vtfs_inode_data *inode_data;
    char *response_buffer;
    char *ino_str;
    
    inode_data = vtfs_find_inode(ino);
    if (!inode_data)
        return -ENOENT;
    
    response_buffer = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer) {
        kfree(inode_data);
        return -ENOMEM;
    }
    
    ino_str = kasprintf(GFP_KERNEL, "%lu", inode_data->ino);
    if (!ino_str) {
        kfree(response_buffer);
        kfree(inode_data);
        return -ENOMEM;
    }
    
    vtfs_http_call(ENDPOINT_DELETE_INODE, HTTP_METHOD_DELETE, response_buffer, HTTP_BUFFER_SIZE, 2, 
                   "ino", ino_str,
                   "name", inode_data->name);
    
    kfree(ino_str);
    kfree(response_buffer);
    kfree(inode_data);
    
    return 0;
}

static bool vtfs_dir_is_empty(ino_t dir_ino)
{
    struct vtfs_inode_data *entry;
    bool empty = true;
    char *response_buffer = NULL;
    struct list_head inodes;
    
    INIT_LIST_HEAD(&inodes);
    
    response_buffer = kzalloc(LARGE_HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer)
        return true;
    
    if (vtfs_http_call(ENDPOINT_GET_ALL, HTTP_METHOD_GET, response_buffer, LARGE_HTTP_BUFFER_SIZE, 0) < 0) {
        kfree(response_buffer);
        return true;
    }
    
    if (parse_inode_array(response_buffer, &inodes) != 0) {
        kfree(response_buffer);
        free_inodes_list(&inodes);
        return true;
    }
    
    kfree(response_buffer);
    
    list_for_each_entry(entry, &inodes, list) {
        if (entry->parent_ino == dir_ino) {
            empty = false;
            break;
        }
    }
    
    free_inodes_list(&inodes);
    
    return empty;
}

struct dentry* vtfs_mount(
    struct file_system_type* fs_type, int flags, const char* token, void* data
);

struct dentry* vtfs_lookup(
    struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag
);

static ino_t ino_cnt = ROOT_INO;

int vtfs_unlink(struct inode* parent_inode, struct dentry* child_dentry);
int vtfs_create(
    struct mnt_idmap* idmap,
    struct inode* parent_inode,
    struct dentry* child_dentry,
    umode_t mode,
    bool b
);

int vtfs_mkdir(
    struct mnt_idmap* idmap,
    struct inode* parent_inode,
    struct dentry* child_dentry,
    umode_t mode
);

int vtfs_rmdir(struct inode* parent_inode, struct dentry* child_dentry);

int vtfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);

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
ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t len, loff_t *offset);
ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset);

struct file_system_type vtfs_fs_type = {
    .name = "vtfs",
    .mount = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .permission = vtfs_permission,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir = vtfs_mkdir,
    .rmdir = vtfs_rmdir,
    .link = vtfs_link  
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct file_operations vtfs_file_ops = {
    .read = vtfs_read,
    .write = vtfs_write
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
    struct inode* inode = NULL;
    
    inode_data = vtfs_find_child(parent_inode->i_ino, name);
    
    if (!inode_data) {
        d_add(child_dentry, NULL);
        return NULL;
    }
    
    inode = vtfs_get_inode(parent_inode->i_sb, NULL, 
                          inode_data->mode, inode_data->ino);
    
    kfree(inode_data);
    
    if (!inode) {
        d_add(child_dentry, NULL);
        return NULL;
    }

    d_add(child_dentry, inode);
    
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
    struct vtfs_inode_data *inode_data;
    struct inode* inode;
    
    if (vtfs_find_child(parent_inode->i_ino, name)) {
        return -EEXIST;
    }
  
    ino = ++ino_cnt;
    
    mode |= S_IFREG;
    inode_data = vtfs_create_inode(ino, mode, name, parent_inode->i_ino);
    if (!inode_data)
        return -ENOMEM;
    
    inode = vtfs_get_inode(parent_inode->i_sb, NULL, mode, ino);
    if (!inode) {
        kfree(inode_data);
        return -ENOMEM;
    }
    
    kfree(inode_data);
    d_add(child_dentry, inode);
    
    return 0;
}

int vtfs_mkdir(
    struct mnt_idmap* idmap,
    struct inode* parent_inode,
    struct dentry* child_dentry,
    umode_t mode
) {
    const char* name = child_dentry->d_name.name;
    ino_t ino;
    struct vtfs_inode_data *inode_data;
    struct inode* inode;
    
    if (vtfs_find_child(parent_inode->i_ino, name)) {
        return -EEXIST;
    }
    
    ino = ++ino_cnt;
    
    mode |= S_IFDIR;
    inode_data = vtfs_create_inode(ino, mode, name, parent_inode->i_ino);
    if (!inode_data)
        return -ENOMEM;
    
    inode = vtfs_get_inode(parent_inode->i_sb, NULL, mode, ino);
    if (!inode) {
        kfree(inode_data);
        return -ENOMEM;
    }
    
    set_nlink(inode, 2);
    kfree(inode_data);
    d_add(child_dentry, inode);
    
    return 0;
}

int vtfs_unlink(struct inode* parent_inode, struct dentry* child_dentry) {
    const char* name = child_dentry->d_name.name;
    struct vtfs_inode_data *child;
    struct vtfs_inode_data *entry;
    char *response_buffer = NULL;
    char *del = NULL;
    char *ino_str = NULL;
    struct list_head inodes;
    int link_count = 0;
    
    child = vtfs_find_child(parent_inode->i_ino, name);
    if (!child)
        return -ENOENT;
    
    if (S_ISDIR(child->mode)) {
        kfree(child);
        return -EISDIR;
    }
    
    del = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!del) {
        kfree(child);
        return -ENOMEM;
    }
    
    ino_str = kasprintf(GFP_KERNEL, "%lu", child->ino);
    if (!ino_str) {
        kfree(del);
        kfree(child);
        return -ENOMEM;
    }
    
    vtfs_http_call(ENDPOINT_DELETE_INODE, HTTP_METHOD_DELETE, del, HTTP_BUFFER_SIZE, 2, 
                   "ino", ino_str,
                   "name", child->name);
    
    kfree(del);
    kfree(ino_str);
    
    response_buffer = kzalloc(LARGE_HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer) {
        kfree(child);
        return -ENOMEM;
    }
    
    INIT_LIST_HEAD(&inodes);
    
    if (vtfs_http_call(ENDPOINT_GET_ALL, HTTP_METHOD_GET, response_buffer, LARGE_HTTP_BUFFER_SIZE, 0) < 0) {
        kfree(response_buffer);
        kfree(child);
        return -EIO;
    }
    
    if (parse_inode_array(response_buffer, &inodes) != 0) {
        kfree(response_buffer);
        free_inodes_list(&inodes);
        kfree(child);
        return -EIO;
    }
    
    kfree(response_buffer);
    
    list_for_each_entry(entry, &inodes, list) {
        if (entry->ino == child->ino) {
            link_count++;
        }
    }
    
    free_inodes_list(&inodes);
    
    if (link_count == 0) {
        del = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
        if (del) {
            ino_str = kasprintf(GFP_KERNEL, "%lu", child->ino);
            if (ino_str) {
                vtfs_http_call(ENDPOINT_FILES, HTTP_METHOD_DELETE, del, HTTP_BUFFER_SIZE, 1, 
                             "ino", ino_str);
                kfree(ino_str);
            }
            kfree(del);
        }
    }
    
    if (link_count > 0 && child_dentry->d_inode) {
        drop_nlink(child_dentry->d_inode);
    }
    
    kfree(child);
    
    return 0;
}

int vtfs_rmdir(struct inode* parent_inode, struct dentry* child_dentry) {
    const char* name = child_dentry->d_name.name;
    struct vtfs_inode_data *child;
    int ret;
    
    child = vtfs_find_child(parent_inode->i_ino, name);
    if (!child)
        return -ENOENT;
    
    if (!S_ISDIR(child->mode)) {
        kfree(child);
        return -ENOTDIR;
    }
    
    if (!vtfs_dir_is_empty(child->ino)) {
        kfree(child);
        return -ENOTEMPTY;
    }
    
    ret = vtfs_remove_inode(child->ino);
    kfree(child);
    
    return ret;
}

int vtfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
    struct inode *inode = old_dentry->d_inode;
    const char *new_name = new_dentry->d_name.name;
    struct vtfs_inode_data *inode_data;
    struct vtfs_inode_data *new_link;
    
    inode_data = vtfs_find_inode(inode->i_ino);
    if (!inode_data)
        return -ENOENT;
    
    if (!S_ISREG(inode_data->mode)) {
        kfree(inode_data);
        return -EPERM;
    }
    
    if (vtfs_find_child(dir->i_ino, new_name)) {
        kfree(inode_data);
        return -EEXIST;
    }
    
    new_link = vtfs_create_inode(
        inode_data->ino, inode_data->mode, new_name, dir->i_ino
    );
    
    kfree(inode_data);
    
    if (!new_link)
        return -ENOMEM;
    
    inc_nlink(inode);
    kfree(new_link);
    
    d_instantiate(new_dentry, igrab(inode));
    
    return 0;
}

int vtfs_fill_super(struct super_block* sb, void* data, int silent) {
    struct vtfs_inode_data *root_data;
    struct inode* inode;
    
    root_data = vtfs_create_inode(ROOT_INO, S_IFDIR | 0777, "", 0);
    if (!root_data)
        return -ENOMEM;
    
    inode = vtfs_get_inode(sb, NULL, S_IFDIR | 0777, ROOT_INO);
    kfree(root_data);
    
    if (!inode)
        return -ENOMEM;
    
    sb->s_root = d_make_root(inode);
    if (sb->s_root == NULL) {
        iput(inode);
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
    } else {
        inode->i_op = &vtfs_inode_ops;
        inode->i_fop = &vtfs_file_ops;
    }

    return inode;
}

int vtfs_iterate(struct file* filp, struct dir_context* ctx) {
    struct dentry* dentry = filp->f_path.dentry;
    struct inode* inode = dentry->d_inode;
    struct vtfs_inode_data *entry;
    struct list_head inodes;
    char *response_buffer = NULL;
    int skip_count = 0;
    int processed = 0;

    if (ctx->pos == 0) {
        if (!dir_emit(ctx, ".", 1, inode->i_ino, DT_DIR)) {
            return 0;
        }
        ctx->pos++;
    }
    
    if (ctx->pos == 1) {
        struct inode* parent_inode = dentry->d_parent->d_inode;
        ino_t parent_ino = parent_inode ? parent_inode->i_ino : 2;
        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR)) {
            return 0;
        }
        ctx->pos++;
    }
    
    if (ctx->pos >= 2) {
        skip_count = (int)ctx->pos - 2;
    }
    
    INIT_LIST_HEAD(&inodes);
    
    response_buffer = kzalloc(LARGE_HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer) {
        return 0;
    }
    
    if (vtfs_http_call(ENDPOINT_GET_ALL, HTTP_METHOD_GET, response_buffer, LARGE_HTTP_BUFFER_SIZE, 0) < 0) {
        kfree(response_buffer);
        return 0;
    }
    
    if (parse_inode_array(response_buffer, &inodes) != 0) {
        kfree(response_buffer);
        free_inodes_list(&inodes);
        return 0;
    }
    
    kfree(response_buffer);
    
    list_for_each_entry(entry, &inodes, list) {
        if (entry->parent_ino != inode->i_ino)
            continue;
            
        if (processed < skip_count) {
            processed++;
            continue;
        }
        
        unsigned char type = DT_UNKNOWN;
        if (S_ISDIR(entry->mode)) {
            type = DT_DIR;
        } else if (S_ISREG(entry->mode)) {
            type = DT_REG;
        } else if (S_ISLNK(entry->mode)) {
            type = DT_LNK;
        }
        
        if (!dir_emit(ctx, entry->name, strlen(entry->name), entry->ino, type)) {
            free_inodes_list(&inodes);
            return 0;
        }
        
        ctx->pos++;
        processed++;
    }
    
    free_inodes_list(&inodes);
    
    return 0;
}

ssize_t vtfs_write(struct file *filp,
                   const char __user *buffer,
                   size_t len,
                   loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    char *kbuf = NULL;
    char *base64_buf = NULL;
    char *response_buffer = NULL;
    char *ino_str = NULL;
    bool append;
    ssize_t ret = 0;
    size_t base64_len;

    if (len == 0)
        return 0;

    append = filp->f_flags & O_APPEND;

    kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buffer, len)) {
        ret = -EFAULT;
        goto out;
    }

    base64_len = (len + 2) / 3 * 4;
    base64_buf = kmalloc(base64_len + 1, GFP_KERNEL);
    if (!base64_buf) {
        ret = -ENOMEM;
        goto out;
    }

    ret = base64_encode(kbuf, len, base64_buf);
    if (ret < 0) {
        pr_err("Failed to encode base64: %ld\n", ret);
        goto out;
    }
    base64_buf[base64_len] = '\0';

    ino_str = kasprintf(GFP_KERNEL, "%lu", inode->i_ino);
    if (!ino_str) {
        ret = -ENOMEM;
        goto out;
    }

    response_buffer = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer) {
        ret = -ENOMEM;
        goto out;
    }

    if (append) {
        ret = vtfs_http_call(
            ENDPOINT_FILES,
            HTTP_METHOD_PUT,
            response_buffer,
            HTTP_BUFFER_SIZE,
            2,
            "ino", ino_str,
            "addData", base64_buf
        );
    }

    else if (*offset == 0) {
        ret = vtfs_http_call(
            ENDPOINT_FILES,
            HTTP_METHOD_POST,
            response_buffer,
            HTTP_BUFFER_SIZE,
            2,
            "ino", ino_str,
            "data", base64_buf
        );
    }
    else {
        ret = -ESPIPE;
        goto out;
    }

    if (ret < 0)
        goto out;

    *offset += len;
    ret = len;

out:
    kfree(response_buffer);
    kfree(ino_str);
    kfree(base64_buf);
    kfree(kbuf);
    return ret;
}

ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset)
{
    struct inode *inode = file_inode(filp);
    struct file_data fdata = {0};
    char *response_buffer = NULL;
    char *ino_str = NULL;
    int64_t http_ret;
    int ret;
    
    response_buffer = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer)
        return -ENOMEM;
    
    ino_str = kasprintf(GFP_KERNEL, "%lu", inode->i_ino);
    if (!ino_str) {
        kfree(response_buffer);
        return -ENOMEM;
    }
    
    http_ret = vtfs_http_call(ENDPOINT_FILE_BY_INO, HTTP_METHOD_GET, response_buffer, HTTP_BUFFER_SIZE, 1,
                              "ino", ino_str);
    kfree(ino_str);
    
    if (http_ret < 0) {
        kfree(response_buffer);
        return -ENOENT;
    }
    
    ret = parse_json_file_data(response_buffer, &fdata);
    kfree(response_buffer);
    
    if (ret < 0)
        return ret;
    
    if (!fdata.data) {
        return 0;
    }
    
    if (*offset >= fdata.size) {
        kfree(fdata.data);
        return 0;
    }
    
    if (*offset + len > fdata.size)
        len = fdata.size - *offset;
    
    if (copy_to_user(buffer, fdata.data + *offset, len)) {
        kfree(fdata.data);
        return -EFAULT;
    }
    
    *offset += len;
    kfree(fdata.data);
    
    return len;
}

void vtfs_kill_sb(struct super_block* sb) {
    printk(KERN_INFO "[" MODULE_NAME "]: Super block destroyed. Unmount successful.\n");
}

int vtfs_permission(struct mnt_idmap* idmap, struct inode* inode, int mask) {
    return 0;
}

static int __init vtfs_init(void) {
    char *ino = kzalloc(INO_BUFFER_SIZE, GFP_KERNEL);
    if (!ino)
        return -ENOMEM;
        
    if (vtfs_http_call(ENDPOINT_GET_MAX_INO, HTTP_METHOD_GET, ino, INO_BUFFER_SIZE, 0) >= 0) {
        ino_cnt = simple_strtol(ino, NULL, 10);
    }
    kfree(ino);
    
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
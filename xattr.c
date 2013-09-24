#include "wrapfs.h"
#include <linux/err.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <linux/string.h>
#include <linux/types.h>


static int init_desc(struct hash_desc *desc)
{
  int rc;
  desc->tfm=crypto_alloc_hash("md5",0,CRYPTO_ALG_ASYNC);
  if(IS_ERR(desc->tfm))
  {
    printk("failed to load\n");
    rc=PTR_ERR(desc->tfm);
    return rc;
  }
  desc->flags=0;
  rc=crypto_hash_init(desc);
  if(rc)
    crypto_free_hash(desc->tfm);
  return rc;
}

void *wrapfs_xattr_alloc(size_t size, size_t limit)
{
 void *ptr;

 if (size > limit)
   return ERR_PTR(-E2BIG);

           if (!size)              /* size request, no buffer is needed */
 return NULL;

 ptr = kmalloc(size, GFP_KERNEL);
 if (unlikely(!ptr))
   return ERR_PTR(-ENOMEM);
 return ptr;
}

ssize_t wrapfs_getxattr(struct dentry *dentry, const char *name, void *value,
  size_t size)
{
 struct dentry *lower_dentry = NULL;
 struct path lower_path;
 int err = -EOPNOTSUPP;
 wrapfs_get_lower_path(dentry,&lower_path);
 lower_dentry=lower_path.dentry;

 err = vfs_getxattr(lower_dentry, (char *) name, value, size);
 if(!err || err<0)
 {

  err=-ENODATA;
}

wrapfs_check_dentry(dentry);
wrapfs_put_lower_path(dentry,&lower_path);
return err;
}


int wrapfs_setxattr(struct dentry *dentry, const char *name,
  const void *value, size_t size, int flags)
{
 struct dentry *lower_dentry = NULL;
 struct path lower_path;
 int xattr,rc,rbuf_len,userid;
 struct inode *inode = NULL;
 int err = -EOPNOTSUPP,i;
 void *val;
 loff_t i_size,offset=0;
 char *rbuf=NULL;
 unsigned char *digest=NULL;
 struct scatterlist sg[1];
 struct file *lower_file=NULL;
 struct hash_desc desc;




 if(!strcmp(name,"user.has_integrity")) 
 {
  userid=current_euid();
  
  if(userid!=0)
  {
    printk("Only root users can set or modify user.has_integrity attribute\n");
    return -EACCES;
  }
  
  if(size!=1)
  {
    printk("You have to enter either 0 or a 1 as value for user.has_integrity\n");
    return -EINVAL;
  }

  if(strncmp((char *)value,"0",1)!=0 && strncmp((char *)value,"1",1)!=0)
  {
    printk("You have to enter either 0 or a 1 as value for user.has_integrity\n");
    return -EINVAL;
  }
  inode = dentry->d_inode;
  if(!strncmp((char *)value,"0",1))

  {
   wrapfs_get_lower_path(dentry,&lower_path);

   lower_dentry=lower_path.dentry;

   err = vfs_setxattr(lower_dentry, (char *) name, (void *) value,
    size, flags);

   val=kmalloc(16,GFP_KERNEL);
   if(val==NULL)
   {
    err=-ENOMEM;
    goto out;
  }
  xattr=vfs_getxattr(lower_dentry, "user.integrity_val", val,16 );
  if(xattr<=0)
  {
    printk("The user.integrity_val attribute does not exist and thus need not be removed\n");
    err=-ENODATA;
  }
  else
  {
    printk("As the has_integrity value is being set to 0, the integrity_val EA is removed\n");
    err=vfs_removexattr(lower_dentry, "user.integrity_val");
  }

  kfree(val);
  
}

else if(!strncmp((char *)value,"1",1) && S_ISREG(inode->i_mode))
{
  wrapfs_get_lower_path(dentry,&lower_path);
  lower_dentry=lower_path.dentry;
  err = vfs_setxattr(lower_dentry, (char *) name, (void *) value,
    size, flags);
                  //compute md5
  lower_file=dentry_open(lower_dentry,lower_path.mnt,O_RDONLY,current_cred());
  if(!lower_file || IS_ERR(lower_file))
  {
    printk("file pointer error %d\n",(int)PTR_ERR(lower_file));
    err = PTR_ERR(lower_file);
    goto out;
  }

  rc=init_desc(&desc);
  
  if(rc)
  {
    printk("Error initializing crypto hash; rc=[%d]\n",rc);

    goto out;
  }
  rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);
  digest=kmalloc(16,GFP_KERNEL);
  if(!rbuf)
  {
    crypto_free_hash(desc.tfm);
    
    err=-ENOMEM;
    goto out;
  }
  i_size=i_size_read(lower_file->f_dentry->d_inode);
  while(offset<i_size)

  {

    rbuf_len=kernel_read(lower_file,offset,rbuf,PAGE_SIZE);
    
    if(rbuf_len<0)
    {
      printk("rbuf_len is less than 0\n");
      rc=rbuf_len;
      break;

    }
    if(rbuf_len==0)
    {
      printk("rbuflen is zero\n");
      break;
    }
    offset+=rbuf_len;
    sg_init_one(sg,rbuf,rbuf_len);
    rc=crypto_hash_update(&desc,sg,rbuf_len);
    if(rc)
    {
      crypto_free_hash(desc.tfm);
      kfree(rbuf);
      kfree(digest);
      err=rc;
      goto out;

    }

  }
  kfree(rbuf);
  if(!rc)
    rc=crypto_hash_final(&desc,digest);
  if(rc)
  {
    printk("Error in computing crypto hash\n");

    crypto_free_hash(desc.tfm);
    kfree(digest); 
    err=rc;
    goto out;

  }
  printk("The computed integrity value is ");
  for(i=0;i<16;i++)
  {
    printk("%x",digest[i]);
  }
  printk("\n");
  err=vfs_setxattr(lower_dentry,"user.integrity_val",(void *)digest,16,flags);
  kfree(digest);
  
}
}
else if(!strcmp(name,"user.integrity_val"))
{
  printk("You cannot compute or modify the check sum\n");
  return -EACCES;
}
else
{
  printk("You are supposed to set only the user.has_integrity extended attribute\n");
  return -EACCES;
}


out:
wrapfs_check_dentry(dentry);
wrapfs_put_lower_path(dentry,&lower_path);
return err;
}

int wrapfs_removexattr(struct dentry *dentry, const char *name)
{
  struct dentry *lower_dentry = NULL;
  struct path lower_path;
  int userid;
  struct inode *inode=NULL;
  int err = -EOPNOTSUPP;
  wrapfs_get_lower_path(dentry,&lower_path);
  lower_dentry=lower_path.dentry;
  inode=dentry->d_inode;

  if(!strcmp(name,"user.has_integrity") && S_ISREG(inode->i_mode))
  {

    userid=current_euid();
    if(userid!=0)
    {
      err=-EACCES;
      goto out;
    }
    err = vfs_removexattr(lower_dentry, "user.integrity_val");
    err=vfs_removexattr(lower_dentry, (char *)name);
  }
  else if(!strcmp(name,"user.integrity_val"))
  {
    printk("You are not permitted to remove this EA\n");
    err=-EACCES;
    goto out;
  }


  out:
  wrapfs_check_dentry(dentry);
  wrapfs_put_lower_path(dentry,&lower_path);
  return err;
}

  /*
   * BKL held by caller.
   * dentry->d_inode->i_mutex locked
   */
   ssize_t wrapfs_listxattr(struct dentry *dentry, char *list, size_t size)
   {
    struct dentry *lower_dentry = NULL;
    struct path lower_path;
    int err = -EOPNOTSUPP;
    char *encoded_list = NULL;
    wrapfs_get_lower_path(dentry,&lower_path);
    lower_dentry=lower_path.dentry;
    encoded_list = list;
    err = vfs_listxattr(lower_dentry, encoded_list, size);
    wrapfs_check_dentry(dentry);
    wrapfs_put_lower_path(dentry,&lower_path);
    return err;
  }

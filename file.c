/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

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


 static ssize_t wrapfs_read(struct file *file, char __user *buf,
 	size_t count, loff_t *ppos)
 {
 	int err;
 	struct file *lower_file;
 	struct dentry *dentry = file->f_path.dentry;

 	lower_file = wrapfs_lower_file(file);
 	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
 	if (err >= 0)
 		fsstack_copy_attr_atime(dentry->d_inode,
 			lower_file->f_path.dentry->d_inode);

 	return err;
 }

 static ssize_t wrapfs_write(struct file *file, const char __user *buf,
 	size_t count, loff_t *ppos)
 {
 	int err = 0;
 	struct file *lower_file;

 	struct dentry *dentry = file->f_path.dentry;
 	WRAPFS_I(dentry->d_inode)->write_flag=1;

 	lower_file = wrapfs_lower_file(file);
 	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
 	if (err >= 0) {
 		fsstack_copy_inode_size(dentry->d_inode,
 			lower_file->f_path.dentry->d_inode);
 		fsstack_copy_attr_times(dentry->d_inode,
 			lower_file->f_path.dentry->d_inode);
 	}

 	return err;
 }

 static int wrapfs_readdir(struct file *file, void *dirent, filldir_t filldir)
 {
 	int err = 0;
 	struct file *lower_file = NULL;
 	struct dentry *dentry = file->f_path.dentry;

 	lower_file = wrapfs_lower_file(file);
 	err = vfs_readdir(lower_file, filldir, dirent);
 	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
 	fsstack_copy_attr_atime(dentry->d_inode,
 		lower_file->f_path.dentry->d_inode);
 	return err;
 }

 static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
 	unsigned long arg)
 {
 	long err = -ENOTTY;
 	struct file *lower_file;

 	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
 	if (!lower_file || !lower_file->f_op)
 		goto out;
 	if (lower_file->f_op->unlocked_ioctl)
 		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

 	out:
 	return err;
 }

#ifdef CONFIG_COMPAT
 static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
 	unsigned long arg)
 {
 	long err = -ENOTTY;
 	struct file *lower_file;

 	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
 	if (!lower_file || !lower_file->f_op)
 		goto out;
 	if (lower_file->f_op->compat_ioctl)
 		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

 	out:
 	return err;
 }
#endif

 static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
 {
 	int err = 0;
 	bool willwrite;
 	struct file *lower_file;
 	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
 	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
lower_file = wrapfs_lower_file(file);
if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
	err = -EINVAL;
	printk(KERN_ERR "wrapfs: lower file system does not "
		"support writeable mmap\n");
	goto out;
}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	 if (!WRAPFS_F(file)->lower_vm_ops) {
	 	err = lower_file->f_op->mmap(lower_file, vma);
	 	if (err) {
	 		printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
	 		goto out;
	 	}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	 	err = do_munmap(current->mm, vma->vm_start,
	 		vma->vm_end - vma->vm_start);
	 	if (err) {
	 		printk(KERN_ERR "wrapfs: do_munmap failed %d\n", err);
	 		goto out;
	 	}
	 }

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	 file_accessed(file);
	 vma->vm_ops = &wrapfs_vm_ops;
	 vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &wrapfs_aops; /* set our aops */
	if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
	 WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

	 out:
	 return err;
	}




	static int wrapfs_open(struct inode *inode, struct file *file)
	{
		int err = 0;
		int i,retval,rc,rbuf_len;
		struct file *lower_file = NULL;
		struct path lower_path;
		unsigned char *val;
		loff_t i_size,offset=0;
		bool flag=0;
		
		char *rbuf=NULL;
		struct scatterlist sg[1];
		struct hash_desc desc;
		unsigned char *md5intvalue;
		unsigned char *buf;
		struct dentry *lower_dentry=NULL;
		
		struct dentry *dentry = file->f_path.dentry;

	// don't open unhashed/deleted files 
		if (d_unhashed(file->f_path.dentry)) {
			err = -ENOENT;
			goto out_err;

		}

		file->private_data =
		kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
		if (!WRAPFS_F(file)) {
			err = -ENOMEM;
			goto out_err;
		}
		wrapfs_get_lower_path(file->f_path.dentry, &lower_path);
		lower_dentry=lower_path.dentry;
		lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
			O_RDONLY, current_cred());
		if (IS_ERR(lower_file)) {
			err = PTR_ERR(lower_file);
			lower_file = wrapfs_lower_file(file);
			if (lower_file) {
				flag=1;
				wrapfs_set_lower_file(file, NULL);
			fput(lower_file); //fput calls dput for lower_dentry 
			goto open;
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(WRAPFS_F(file));
	
	
	fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
	if (S_ISDIR(inode->i_mode))
	{
		printk("This is a directory. The directory name is %s\n",file->f_dentry->d_name.name);
	}
	if(S_ISREG(inode->i_mode))
	{
		
		printk("This is a regular file. The file name is %s\n",file->f_dentry->d_name.name);
		val=kmalloc(1,GFP_KERNEL);
		if(val==NULL)
		{
			err=-ENOMEM;
			goto out_err;
		}
		retval=vfs_getxattr(lower_path.dentry, "user.has_integrity", val,1 );
		if(retval<=0)
		{
			if(retval==-ENODATA)
			{
				UDBG;
				goto open;
			}
			kfree(val);
			goto out_err;	
			
		}
		UDBG;
		if(strncmp((char *)val,"0",1)!=0 && strncmp((char *)val,"1",1)!=0)
		{
			printk("Invalid value of user.has_integrity EA\n");
			kfree(val);
			err=-EIO;
			goto out_err;
		}
		else if(!strncmp((char *)val,"1",1))
		{
			if(	WRAPFS_I(dentry->d_inode)->write_flag==1)
			{
				printk("The write flag is set and thus integrity need not be compared\n");
				kfree(val);
				goto open;
			}
			buf=kmalloc(16,GFP_KERNEL);

			if(buf==NULL)
			{
				printk("There is no kernel memory available\n");
				kfree(val);

				err=-ENOMEM;
				goto out_err;

			}
			retval=vfs_getxattr(lower_path.dentry,"user.integrity_val",buf,16);

			if(retval<=0)
			{
				
				kfree(val);

				kfree(buf);
				err=-EIO;
				goto out_err;


			}

			md5intvalue=kmalloc(16,GFP_KERNEL);
			if(md5intvalue==NULL)
			{
				err=-ENOMEM;
				goto out_err;
			}

			rc=init_desc(&desc);
			if(rc)
			{
				printk("Error initializing crypto hash; rc=[%d]\n",rc);
				kfree(val);
				kfree(buf);
				goto out_err;
			}
			rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);
			md5intvalue=kmalloc(16,GFP_KERNEL);
			if(!rbuf)
			{
				crypto_free_hash(desc.tfm);
				kfree(val);
				kfree(buf);
				err=-ENOMEM;
				goto out_err;
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
					kfree(val);
					kfree(buf);
					kfree(rbuf);
					kfree(md5intvalue);

					err=rc;
					goto out_err;

				}

			}

			kfree(rbuf);
			if(!rc)
				rc=crypto_hash_final(&desc,md5intvalue);
			if(rc)
			{
				printk("Error in computing crypto hash\n");

				crypto_free_hash(desc.tfm);
				kfree(val);
				kfree(buf);

				kfree(md5intvalue);

				err=rc;
				goto out_err;

			}
			

			printk("The computed integrity value is ");
			for(i=0;i<16;i++)
			{
				printk("%x",md5intvalue[i]);
			}
			printk("\n");


			if(memcmp(md5intvalue,buf,16))
			{
				printk("The checksum of the file does not match the stored checksum and hence your file has been modified\n");
				kfree(buf);
				kfree(val);
				kfree(md5intvalue);
				err=-EPERM;
				goto out_err;

			}
			printk("The existing md5 value and the newly computed value match\n");
			kfree(md5intvalue);
			kfree(buf);
			kfree(val);
		}
		else
		{
			kfree(val);
			goto open;
		}

	}
	if (S_ISLNK(inode->i_mode))
	{
		printk("This is a link. The file name is %s\n",file->f_dentry->d_name.name);
	}
	open:
	if(flag==0)
		wrapfs_put_lower_path(file->f_path.dentry, &lower_path);
	flag=1;
	wrapfs_get_lower_path(file->f_path.dentry, &lower_path);

	lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
		file->f_flags, current_cred());

	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = wrapfs_lower_file(file);
		if (lower_file) {
			wrapfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(WRAPFS_F(file));
	else {
		fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
	}

	out_err:
	if ( flag == 0) { 
		wrapfs_put_lower_path(file->f_path.dentry, &lower_path);
	}

	return err;
}


static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);

	return err;
}
/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
	int rbuf_len,rc,i,err=0,retval;
	struct file *lower_file=NULL;
	loff_t i_size,offset=0;
	char *rbuf=NULL;
	unsigned char *val;
	bool flag=0;
	struct path lower_path;
	struct scatterlist sg[1];
	
	struct hash_desc desc;
	unsigned char *md5intvalue=NULL;
	
	struct dentry *dentry = file->f_path.dentry;
	wrapfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
		O_RDONLY, current_cred());
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = wrapfs_lower_file(file);
		if (lower_file) {
			wrapfs_set_lower_file(file, NULL);
			flag=1;
			fput(lower_file);
			goto open; // fput calls dput for lower_dentry 
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
	}
	if (err)
		kfree(WRAPFS_F(file));
	
	if(S_ISREG(inode->i_mode))
	{
		val=kmalloc(1,GFP_KERNEL);
		if(val==NULL)
		{
			err=-ENOMEM;
			goto out_err;
		}
		retval=vfs_getxattr(lower_path.dentry, "user.has_integrity",(char *) val,1 );
		if(retval<=0)
		{
			if(retval==-ENODATA)
			{
				
				goto open;
			}
			kfree(val);
			err=-ENODATA;
			goto out_err;
		}
		if(!strncmp((char *)val,"1",1))
		{
			if(	WRAPFS_I(dentry->d_inode)->write_flag==1)
			{


				rc=init_desc(&desc);
				if(rc)
				{
					printk("Error initializing crypto hash; rc=[%d]\n",rc);
					kfree(val);
					goto out_err;

				}
				rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);
				md5intvalue=kmalloc(16,GFP_KERNEL);
				if(!rbuf)
				{
					crypto_free_hash(desc.tfm);
					kfree(val);
					err=-ENOMEM;
					goto out_err;
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
						kfree(val);
						kfree(rbuf);
						kfree(md5intvalue);

						err=rc;
						goto out_err;

					}

				}

				kfree(rbuf);
				if(!rc)
					rc=crypto_hash_final(&desc,md5intvalue);
				if(rc)
				{
					printk("Error in computing crypto hash\n");

					crypto_free_hash(desc.tfm);
					kfree(val);
					kfree(md5intvalue);

					err=rc;
					goto out_err;

				}
				printk("The computed integrity value in is ");
				for(i=0;i<16;i++)
				{
					printk("%x",md5intvalue[i]);
				}
				printk("\n");
				retval=vfs_setxattr(lower_file->f_path.dentry,"user.integrity_val",(void *)md5intvalue,16,0);
				if(retval<0 && retval!=-ENOMEM)
				{
					if(err==-ENODATA)
						err=-EIO;
					kfree(md5intvalue);
					goto out_err;
				}
				else
				{
					kfree(val);
					goto open;
				}
			}
		}
	}
	open:
	if(flag==0)
		wrapfs_put_lower_path(file->f_path.dentry, &lower_path);
	flag=1;
	wrapfs_get_lower_path(file->f_path.dentry, &lower_path);

	lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
		file->f_flags, current_cred());

	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = wrapfs_lower_file(file);
		if (lower_file) {
			wrapfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(WRAPFS_F(file));
	else {
		fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
	}
	
	out_err:
	if(flag==0)
		wrapfs_put_lower_path(file->f_path.dentry, &lower_path);
	WRAPFS_I(dentry->d_inode)->write_flag=0;
	return err;
}





static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
	int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = wrapfs_lower_file(file);
	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	wrapfs_put_lower_path(dentry, &lower_path);
	out:
	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 */

#include <linux/kernel.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "ion.h"
#include "ion_system_secure_heap.h"

#ifdef CONFIG_ION_LEGACY
#include "ion_legacy.h"
#endif

/*
 * Legacy Qualcomm msm_ion cache maintenance ioctls.
 *
 * The old camera HAL (libmmqjpeg_codec.so / libqomx_jpegenc_pipe.so) calls
 * these on ION fds before/after hardware DMA operations. The 4.4 msm_ion
 * driver handled them directly; in 4.19 we translate them to dma_buf CPU access APIs.
 *
 * The HAL passes the ION fd (not handle) in the fd field of these structs.
 */
#define ION_IOC_MSM_MAGIC 'M'

struct ion_flush_data {
	__u64 handle;
	__u64 fd;
	__u64 offset;
	__u64 length;
	int direction;
};

struct ion_sync_data {
	__u64 handle;
	__u32 fd;
	__u32 flags;
};

#define ION_IOC_SYNC		_IOWR(ION_IOC_MSM_MAGIC, 5, struct ion_sync_data)
#define ION_IOC_CLEAN_CACHES	_IOWR(ION_IOC_MSM_MAGIC, 6, struct ion_flush_data)
#define ION_IOC_INV_CACHES	_IOWR(ION_IOC_MSM_MAGIC, 7, struct ion_flush_data)

static int ion_legacy_cache_ops(unsigned int cmd,
				 struct ion_flush_data __user *user_data)
{
	struct ion_flush_data data;
	struct dma_buf *dmabuf;
	enum dma_data_direction dir = DMA_BIDIRECTIONAL;
	int ret;

	if (copy_from_user(&data, user_data, sizeof(data)))
		return -EFAULT;

	dmabuf = dma_buf_get((int)data.fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	if (data.direction == 1)
		dir = DMA_TO_DEVICE;
	else if (data.direction == 2)
		dir = DMA_FROM_DEVICE;

	if (cmd == ION_IOC_CLEAN_CACHES) {
		if (data.length)
			ret = dma_buf_end_cpu_access_partial(dmabuf, dir,
							     (unsigned int)data.offset,
							     (unsigned int)data.length);
		else
			ret = dma_buf_end_cpu_access(dmabuf, dir);
	} else {
		if (data.length)
			ret = dma_buf_begin_cpu_access_partial(dmabuf, dir,
							       (unsigned int)data.offset,
							       (unsigned int)data.length);
		else
			ret = dma_buf_begin_cpu_access(dmabuf, dir);
	}

	dma_buf_put(dmabuf);
	return ret;
}

static int ion_legacy_sync(struct ion_sync_data __user *user_data)
{
	struct ion_sync_data data;
	struct dma_buf *dmabuf;
	int ret;

	if (copy_from_user(&data, user_data, sizeof(data)))
		return -EFAULT;

	dmabuf = dma_buf_get(data.fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	ret = dma_buf_end_cpu_access(dmabuf, DMA_BIDIRECTIONAL);
	dma_buf_put(dmabuf);
	return ret;
}

union ion_ioctl_arg {
	struct ion_allocation_data allocation;
	struct ion_heap_query query;
	struct ion_prefetch_data prefetch_data;
#ifdef CONFIG_ION_LEGACY
	struct ion_fd_data fd;
	struct ion_old_allocation_data old_allocation;
	struct ion_handle_data handle;
#endif
};

static int validate_ioctl_arg(unsigned int cmd, union ion_ioctl_arg *arg)
{
	switch (cmd) {
	case ION_IOC_HEAP_QUERY:
		if (arg->query.reserved0 ||
		    arg->query.reserved1 ||
		    arg->query.reserved2)
			return -EINVAL;
		break;
	default:
		break;
	}

	return 0;
}

/* fix up the cases where the ioctl direction bits are incorrect */
static unsigned int ion_ioctl_dir(unsigned int cmd)
{
	switch (cmd) {
#ifdef CONFIG_ION_LEGACY
	case ION_IOC_FREE:
		return _IOC_WRITE;
#endif
	default:
		return _IOC_DIR(cmd);
	}
}

long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	unsigned int dir;
	union ion_ioctl_arg data;

	dir = ion_ioctl_dir(cmd);

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	/*
	 * The copy_from_user is unconditional here for both read and write
	 * to do the validate. If there is no write for the ioctl, the
	 * buffer is cleared
	 */
	if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = validate_ioctl_arg(cmd, &data);
	if (ret) {
		pr_warn_once("%s: ioctl validate failed\n", __func__);
		return ret;
	}

	if (!(dir & _IOC_WRITE))
		memset(&data, 0, sizeof(data));

	switch (cmd) {
	case ION_IOC_ALLOC:
	{
		int fd;

		fd = ion_alloc_fd(data.allocation.len,
				  data.allocation.heap_id_mask,
				  data.allocation.flags);
		if (fd < 0)
			return fd;

		data.allocation.fd = fd;

		break;
	}
	case ION_IOC_HEAP_QUERY:
		ret = ion_query_heaps(&data.query);
		break;
	case ION_IOC_PREFETCH:
	{
		int ret;

		ret = ion_walk_heaps(data.prefetch_data.heap_id,
				     (enum ion_heap_type)
				     ION_HEAP_TYPE_SYSTEM_SECURE,
				     (void *)&data.prefetch_data,
				     ion_system_secure_heap_prefetch);
		if (ret)
			return ret;
		break;
	}
	case ION_IOC_DRAIN:
	{
		int ret;

		ret = ion_walk_heaps(data.prefetch_data.heap_id,
				     (enum ion_heap_type)
				     ION_HEAP_TYPE_SYSTEM_SECURE,
				     (void *)&data.prefetch_data,
				     ion_system_secure_heap_drain);

		if (ret)
			return ret;
		break;
	}
#ifdef CONFIG_ION_LEGACY
	case ION_OLD_IOC_ALLOC:
	{
		int fd;

		fd = ion_alloc_fd(data.old_allocation.len,
				  data.old_allocation.heap_id_mask,
				  data.old_allocation.flags);
		if (fd < 0)
			return fd;

		data.old_allocation.handle = fd;

		break;
	}
	case ION_IOC_FREE:
		/*
		 * libion passes 0 as the handle to check for this ioctl's
		 * existence and expects -ENOTTY on kernel 4.12+ as an indicator
		 * of having a new ION ABI. We want to use new ION as much as
		 * possible, so pretend that this ioctl doesn't exist when
		 * libion checks for it.
		 */
		if (!data.handle.handle)
			ret = -ENOTTY;

		break;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		data.fd.fd = data.fd.handle;
		break;
	case ION_IOC_IMPORT:
		data.fd.handle = data.fd.fd;
		break;
#endif
	case ION_IOC_CLEAN_CACHES:
	case ION_IOC_INV_CACHES:
		return ion_legacy_cache_ops(cmd,
					 (struct ion_flush_data __user *)arg);
	case ION_IOC_SYNC:
		return ion_legacy_sync(
				(struct ion_sync_data __user *)arg);
	default:
		return -ENOTTY;
	}

	if (dir & _IOC_READ) {
		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}
	return ret;
}

/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <cutils/log.h>
#include <cutils/atomic.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>

#include <sys/ioctl.h>

#include "alloc_device.h"
#include "gralloc_priv.h"
#include "gralloc_helper.h"

#include <linux/ion.h>
#include <ion/ion.h>

#define GRALLOC_ALIGN( value, base ) (((value) + ((base) - 1)) & ~((base) - 1))

static int gralloc_alloc_buffer(alloc_device_t *dev, size_t size, int usage, buffer_handle_t *pHandle)
{
	{
		private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);
		struct ion_handle *ion_hnd;
		unsigned char *cpu_ptr;
		int shared_fd;
		int ret;

		ret = ion_alloc(m->ion_client, size, 0, ION_HEAP_TYPE_DMA_MASK, 0, &ion_hnd);

		if (ret != 0)
		{
			AERR("Failed to ion_alloc from ion_client:%d", m->ion_client);
			return -1;
		}

		ret = ion_share(m->ion_client, ion_hnd, &shared_fd);

		if (ret != 0)
		{
			AERR("ion_share( %d ) failed", m->ion_client);

			if (0 != ion_free(m->ion_client, ion_hnd))
			{
				AERR("ion_free( %d ) failed", m->ion_client);
			}

			return -1;
		}

		cpu_ptr = (unsigned char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);

		if (MAP_FAILED == cpu_ptr)
		{
			AERR("ion_map( %d ) failed", m->ion_client);

			if (0 != ion_free(m->ion_client, ion_hnd))
			{
				AERR("ion_free( %d ) failed", m->ion_client);
			}

			close(shared_fd);
			return -1;
		}

		private_handle_t *hnd = new private_handle_t(private_handle_t::PRIV_FLAGS_USES_ION, usage, size, (int)cpu_ptr, private_handle_t::LOCK_STATE_MAPPED);

		if (NULL != hnd)
		{
			hnd->share_fd = shared_fd;
			hnd->ion_hnd = ion_hnd;
			*pHandle = hnd;
			return 0;
		}
		else
		{
			AERR("Gralloc out of mem for ion_client:%d", m->ion_client);
		}

		close(shared_fd);
		ret = munmap(cpu_ptr, size);

		if (0 != ret)
		{
			AERR("munmap failed for base:%p size: %d", cpu_ptr, size);
		}

		ret = ion_free(m->ion_client, ion_hnd);

		if (0 != ret)
		{
			AERR("ion_free( %d ) failed", m->ion_client);
		}

		return -1;
	}

}

static int alloc_device_alloc(alloc_device_t *dev, int w, int h, int format, int usage, buffer_handle_t *pHandle, int *pStride)
{
	if (!pHandle || !pStride)
	{
		return -EINVAL;
	}

	size_t size;
	size_t stride;

	if (format == HAL_PIXEL_FORMAT_YCrCb_420_SP || format == HAL_PIXEL_FORMAT_YV12)
	{
		switch (format)
		{
			case HAL_PIXEL_FORMAT_YCrCb_420_SP:
			case HAL_PIXEL_FORMAT_YV12:
				stride = GRALLOC_ALIGN(w, 16);
				size = h * (stride + GRALLOC_ALIGN(stride / 2, 16));

				break;

			default:
				return -EINVAL;
		}
	}
	else
	{
		int bpp = 0;

		switch (format)
		{
			case HAL_PIXEL_FORMAT_RGBA_8888:
			case HAL_PIXEL_FORMAT_RGBX_8888:
			case HAL_PIXEL_FORMAT_BGRA_8888:
				bpp = 4;
				break;

			case HAL_PIXEL_FORMAT_RGB_888:
				bpp = 3;
				break;

			case HAL_PIXEL_FORMAT_RGB_565:
#if PLATFORM_SDK_VERSION < 19
			case HAL_PIXEL_FORMAT_RGBA_5551:
			case HAL_PIXEL_FORMAT_RGBA_4444:
#endif
				bpp = 2;
				break;

			default:
				return -EINVAL;
		}

		size_t bpr = GRALLOC_ALIGN(w * bpp, 64);
		size = bpr * h;
		stride = bpr / bpp;
	}

	int err = gralloc_alloc_buffer(dev, size, usage, pHandle);

	if (err < 0)
	{
		return err;
	}

	/* match the framebuffer format */
	if (usage & GRALLOC_USAGE_HW_FB)
	{
#ifdef GRALLOC_16_BITS
		format = HAL_PIXEL_FORMAT_RGB_565;
#else
		format = HAL_PIXEL_FORMAT_BGRA_8888;
#endif
	}

	private_handle_t *hnd = (private_handle_t *)*pHandle;
	int               private_usage = usage & (GRALLOC_USAGE_PRIVATE_0 |
	                                  GRALLOC_USAGE_PRIVATE_1);

	switch (private_usage)
	{
		case 0:
			hnd->yuv_info = MALI_YUV_BT601_NARROW;
			break;

		case GRALLOC_USAGE_PRIVATE_1:
			hnd->yuv_info = MALI_YUV_BT601_WIDE;
			break;

		case GRALLOC_USAGE_PRIVATE_0:
			hnd->yuv_info = MALI_YUV_BT709_NARROW;
			break;

		case (GRALLOC_USAGE_PRIVATE_0 | GRALLOC_USAGE_PRIVATE_1):
			hnd->yuv_info = MALI_YUV_BT709_WIDE;
			break;
	}

	hnd->width = w;
	hnd->height = h;
	hnd->format = format;
	hnd->stride = stride;

	*pStride = stride;
	return 0;
}

static int alloc_device_free(alloc_device_t *dev, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		return -EINVAL;
	}

	private_handle_t const *hnd = reinterpret_cast<private_handle_t const *>(handle);

	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
	{
		private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);

		/* Buffer might be unregistered so we need to check for invalid ump handle*/
		if (0 != hnd->base)
		{
			if (0 != munmap((void *)hnd->base, hnd->size))
			{
				AERR("Failed to munmap handle 0x%x", (unsigned int)hnd);
			}
		}

		close(hnd->share_fd);

		if (0 != ion_free(m->ion_client, hnd->ion_hnd))
		{
			AERR("Failed to ion_free( ion_client: %d ion_hnd: %p )", m->ion_client, hnd->ion_hnd);
		}

		memset((void *)hnd, 0, sizeof(*hnd));

	}

	delete hnd;

	return 0;
}

static int alloc_device_close(struct hw_device_t *device)
{
	alloc_device_t *dev = reinterpret_cast<alloc_device_t *>(device);

	if (dev)
	{
		private_module_t *m = reinterpret_cast<private_module_t *>(device);

		if (0 != ion_close(m->ion_client))
		{
			AERR("Failed to close ion_client: %d", m->ion_client);
		}

		close(m->ion_client);
		delete dev;
	}

	return 0;
}

int alloc_device_open(hw_module_t const *module, const char *name, hw_device_t **device)
{
	alloc_device_t *dev;

	dev = new alloc_device_t;

	if (NULL == dev)
	{
		return -1;
	}

	/* initialize our state here */
	memset(dev, 0, sizeof(*dev));

	/* initialize the procs */
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = const_cast<hw_module_t *>(module);
	dev->common.close = alloc_device_close;
	dev->alloc = alloc_device_alloc;
	dev->free = alloc_device_free;

	private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);
	m->ion_client = ion_open();

	if (m->ion_client < 0)
	{
		AERR("ion_open failed with %s", strerror(errno));
		delete dev;
		return -1;
	}

	*device = &dev->common;

	return 0;
}

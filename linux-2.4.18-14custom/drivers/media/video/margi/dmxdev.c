/* 
 * dmxdev.c - DVB demultiplexer device 
 *
 * Copyright (C) 2000 Ralph  Metzler <ralph@convergence.de>
 *                  & Marcus Metzler <marcus@convergence.de>
                      for convergence integrated media GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <asm/uaccess.h>

#include "cardbase.h"
#include "dmxdev.h"

#ifdef MODULE
MODULE_DESCRIPTION("");
MODULE_AUTHOR("Ralph Metzler, Marcus Metzler");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
MODULE_PARM(debug,"i");
#endif
static int debug = 0;

#define dprintk	if (debug) printk

inline dmxdev_filter_t *
DmxDevFile2Filter(dmxdev_t *dmxdev, struct file *file)
{
        return (dmxdev_filter_t *) file->private_data;
}

inline dmxdev_dvr_t *
DmxDevFile2DVR(dmxdev_t *dmxdev, struct file *file)
{
        return (dmxdev_dvr_t *) file->private_data;
}

static inline void 
DmxDevBufferInit(dmxdev_buffer_t *buffer) 
{
        buffer->data=0;
        buffer->size=8192;
        buffer->pread=0;
        buffer->pwrite=0;
        buffer->error=0;
        init_waitqueue_head(&buffer->queue);
}

static inline int 
DmxDevBufferWrite(dmxdev_buffer_t *buf, uint8_t *src, int len) 
{
        int split;
        int free;
        int todo;

	if (!len)
	        return 0;
	if (!buf->data)
	        return 0;
	
        free=buf->pread-buf->pwrite;
        split=0;
        if (free<=0) {
                free+=buf->size;
                split=buf->size-buf->pwrite;
        }
        if (len>=free) {
		dprintk("dmxdev: buffer overflow\n");
                return -1;
	}
        if (split>=len)
                split=0;
        todo=len;
        if (split) {
                memcpy(buf->data + buf->pwrite, src, split);
                todo-=split;
                buf->pwrite=0;
        }
        memcpy(buf->data + buf->pwrite, src+split, todo);
        buf->pwrite=(buf->pwrite+todo)%buf->size;
        return len;
}

static ssize_t 
DmxDevBufferRead(dmxdev_buffer_t *src, int non_blocking, 
		 char *buf, size_t count, loff_t *ppos)
{
        unsigned long todo=count;
        int split, avail, error;
	
	if (!src->data)
	        return 0;
       	if ((error=src->error)) {
	        src->error=0;
		return error; 
	}

	if (non_blocking && (src->pwrite==src->pread))
	        return -EWOULDBLOCK;

        while (todo>0) {
	        if (non_blocking && (src->pwrite==src->pread))
		        return (count-todo) ? (count-todo) : -EWOULDBLOCK;

	        if (wait_event_interruptible(src->queue,
					     (src->pread!=src->pwrite) ||
					     (src->error))<0)
		        return count-todo;

		if ((error=src->error)) {
		        src->error=0;
			return error; 
		}
		
                split=src->size;
                avail=src->pwrite - src->pread;
                if (avail<0) {
                        avail+=src->size;
                        split=src->size - src->pread;
                }
                if (avail>todo)
                        avail=todo;
                if (split<avail) {
                        if (copy_to_user(buf, src->data+src->pread, split))
                                  return -EFAULT;
                        buf+=split;
                        src->pread=0;
                        todo-=split;
                        avail-=split;
                }
                if (avail) {
                        if (copy_to_user(buf, src->data+src->pread, avail))
                                return -EFAULT;
                        src->pread = (src->pread + avail) % src->size;
                        todo-=avail;
                        buf+=avail;
                }
        }
        return count;
}

static dmx_frontend_t *
get_fe(dmx_demux_t *demux, int type)
{
        struct list_head *head, *pos;

        head=demux->get_frontends(demux);
	if (!head)
	        return 0;
	list_for_each(pos, head)
	        if (DMX_FE_ENTRY(pos)->source==type)
		        return DMX_FE_ENTRY(pos);
	
	return 0;
}

static inline void 
DmxDevDVRStateSet(dmxdev_dvr_t *dmxdevdvr, int state)
{
        spin_lock_irq(&dmxdevdvr->dev->lock);
        dmxdevdvr->state=state;
	spin_unlock_irq(&dmxdevdvr->dev->lock);
}

int 
DmxDevDVROpen(dmxdev_t *dmxdev, struct file *file)
{
        dmx_frontend_t *front;

        down(&dmxdev->mutex);
	if ((file->f_flags&O_ACCMODE)==O_RDWR) {
	        if (!(dmxdev->capabilities&DMXDEV_CAP_DUPLEX)) {
			up(&dmxdev->mutex);
		        return -EOPNOTSUPP;
		}
	}

	if ((file->f_flags&O_ACCMODE)==O_RDONLY) {
	      DmxDevBufferInit(&dmxdev->dvr_buffer);
	      dmxdev->dvr_buffer.size=DVR_BUFFER_SIZE;
	      dmxdev->dvr_buffer.data=vmalloc(DVR_BUFFER_SIZE);
	      if (!dmxdev->dvr_buffer.data) {
		      up(&dmxdev->mutex);
	              return -ENOMEM;
	      }
	}

	if ((file->f_flags&O_ACCMODE)==O_WRONLY) {
	        dmxdev->dvr_orig_fe=dmxdev->demux->frontend;
		
		if (!dmxdev->demux->write) {
			up(&dmxdev->mutex);
			return -EOPNOTSUPP;
		}
		
		front=get_fe(dmxdev->demux, DMX_MEMORY_FE);
		
		if (!front) {
			up(&dmxdev->mutex);
		        return -EINVAL;
		}
		dmxdev->demux->disconnect_frontend(dmxdev->demux);	
		dmxdev->demux->connect_frontend(dmxdev->demux, front);	
	}
        up(&dmxdev->mutex);
        return 0;
}

int 
DmxDevDVRClose(dmxdev_t *dmxdev, struct file *file)
{
        down(&dmxdev->mutex);
	if ((file->f_flags&O_ACCMODE)==O_WRONLY) {
	        dmxdev->demux->disconnect_frontend(dmxdev->demux);	
		dmxdev->demux->connect_frontend(dmxdev->demux, 
						dmxdev->dvr_orig_fe);
	}
	if ((file->f_flags&O_ACCMODE)==O_RDONLY) {
		if (dmxdev->dvr_buffer.data) {
		        void *mem=dmxdev->dvr_buffer.data;
			mb();
			spin_lock_irq(&dmxdev->lock);
			dmxdev->dvr_buffer.data=0;
			spin_unlock_irq(&dmxdev->lock);
		        vfree(mem);
		}
	}
        up(&dmxdev->mutex);
	return 0;
}

ssize_t 
DmxDevDVRWrite(dmxdev_t *dmxdev, struct file *file, 
             const char *buf, size_t count, loff_t *ppos)
{
	int ret;

        if (!dmxdev->demux->write)
	        return -EOPNOTSUPP;
	if ((file->f_flags&O_ACCMODE)!=O_WRONLY)
	        return -EINVAL;
        down(&dmxdev->mutex);
        ret=dmxdev->demux->write(dmxdev->demux, buf, count);
        up(&dmxdev->mutex);
	return ret;
}

ssize_t 
DmxDevDVRRead(dmxdev_t *dmxdev, struct file *file, 
	      char *buf, size_t count, loff_t *ppos)
{
	int ret;

        down(&dmxdev->mutex);
        ret= DmxDevBufferRead(&dmxdev->dvr_buffer, 
			      file->f_flags&O_NONBLOCK, 
			      buf, count, ppos);
        up(&dmxdev->mutex);
	return ret;
}

static inline void 
DmxDevFilterStateSet(dmxdev_filter_t *dmxdevfilter, int state)
{
        spin_lock_irq(&dmxdevfilter->dev->lock);
        dmxdevfilter->state=state;
	spin_unlock_irq(&dmxdevfilter->dev->lock);
}

static int 
DmxDevSetBufferSize(dmxdev_filter_t *dmxdevfilter, unsigned long size)
{
	dmxdev_buffer_t *buf=&dmxdevfilter->buffer;

	if (buf->size==size)
	        return 0;
        if (dmxdevfilter->state>=DMXDEV_STATE_GO)
                return -EBUSY;
	spin_lock_irq(&dmxdevfilter->dev->lock);
        if (buf->data) 
		vfree(buf->data);
	buf->data=0;
	buf->size=size;
	buf->pwrite=buf->pread=0;    
	spin_unlock_irq(&dmxdevfilter->dev->lock);
		
        if (buf->size) {
	        void *mem=vmalloc(dmxdevfilter->buffer.size);

		if (!mem)
		        return -ENOMEM;
	        spin_lock_irq(&dmxdevfilter->dev->lock);
                buf->data=mem;
	        spin_unlock_irq(&dmxdevfilter->dev->lock);
	}
	return 0;
}

static void
DmxDevFilterTimeout(unsigned long data)
{
        dmxdev_filter_t *dmxdevfilter=(dmxdev_filter_t *)data;
	
	dmxdevfilter->buffer.error=-ETIMEDOUT;
        spin_lock_irq(&dmxdevfilter->dev->lock);
	dmxdevfilter->state=DMXDEV_STATE_TIMEDOUT;
        spin_unlock_irq(&dmxdevfilter->dev->lock);
	wake_up(&dmxdevfilter->buffer.queue);
}

static void
DmxDevFilterTimer(dmxdev_filter_t *dmxdevfilter)
{
        struct dmxSctFilterParams *para=&dmxdevfilter->params.sec;
  
	del_timer(&dmxdevfilter->timer);
	if (para->timeout) {
	        dmxdevfilter->timer.function=DmxDevFilterTimeout;
		dmxdevfilter->timer.data=(unsigned long) dmxdevfilter;
		dmxdevfilter->timer.expires=jiffies+1+(HZ/2+HZ*para->timeout)/1000;
		add_timer(&dmxdevfilter->timer);
	}
}

static int 
DmxDevSectionCallback(u8 *buffer1, size_t buffer1_len,
		      u8 *buffer2, size_t buffer2_len,
		      dmx_section_filter_t *filter,
		      dmx_success_t success)
{
        dmxdev_filter_t *dmxdevfilter=(dmxdev_filter_t *) filter->priv;
        int ret;
        
	if (dmxdevfilter->buffer.error)
	        return 0;
	spin_lock(&dmxdevfilter->dev->lock);
	if (dmxdevfilter->state!=DMXDEV_STATE_GO) {
		spin_unlock(&dmxdevfilter->dev->lock);
	        return 0;
	}
	del_timer(&dmxdevfilter->timer);
	dprintk("dmxdev: section callback %02x %02x %02x %02x %02x %02x\n", 
		buffer1[0], buffer1[1], 
		buffer1[2], buffer1[3], 
		buffer1[4], buffer1[5]);
        ret=DmxDevBufferWrite(&dmxdevfilter->buffer, buffer1, buffer1_len);
        if (ret==buffer1_len) {
	        ret=DmxDevBufferWrite(&dmxdevfilter->buffer, buffer2, buffer2_len);
	}
        if (ret<0) {
	        dmxdevfilter->buffer.pwrite=dmxdevfilter->buffer.pread;    
	        dmxdevfilter->buffer.error=-EBUFFEROVERFLOW;
	}
	if (dmxdevfilter->params.sec.flags&DMX_ONESHOT)
	        dmxdevfilter->state=DMXDEV_STATE_DONE;
	spin_unlock(&dmxdevfilter->dev->lock);
	wake_up(&dmxdevfilter->buffer.queue);
	return 0;
}

static int 
DmxDevTSCallback(u8 *buffer1, size_t buffer1_len,
		 u8 *buffer2, size_t buffer2_len,
		 dmx_ts_feed_t *feed,
		 dmx_success_t success)
{
        dmxdev_filter_t *dmxdevfilter=(dmxdev_filter_t *) feed->priv;
	dmxdev_buffer_t *buffer;
        int ret;
        
	if (dmxdevfilter->params.pes.output==DMX_OUT_DECODER)
	        return 0;

	if (dmxdevfilter->params.pes.output==DMX_OUT_TAP)
	        buffer=&dmxdevfilter->buffer;
	else
	        buffer=&dmxdevfilter->dev->dvr_buffer;
	if (buffer->error) {
		wake_up(&buffer->queue);
	        return 0;
	}
        ret=DmxDevBufferWrite(buffer, buffer1, buffer1_len);
        if (ret==buffer1_len) 
	        ret=DmxDevBufferWrite(buffer, buffer2, buffer2_len);
        if (ret<0) {
	        buffer->pwrite=buffer->pread;    
	        buffer->error=-EBUFFEROVERFLOW;
	}
	wake_up(&buffer->queue);
	return 0;
}


/* stop feed but only mark the specified filter as stopped (state set) */

static int 
DmxDevFeedStop(dmxdev_filter_t *dmxdevfilter)
{
	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_SET);

	switch (dmxdevfilter->type) {
	case DMXDEV_TYPE_SEC:
	        del_timer(&dmxdevfilter->timer);
	        dmxdevfilter->feed.sec->stop_filtering(dmxdevfilter->feed.sec);
		break;
	case DMXDEV_TYPE_PES:
	        dmxdevfilter->feed.ts->stop_filtering(dmxdevfilter->feed.ts);
		break;
	default:
	        return -EINVAL;
	}
        return 0;
}


/* start feed associated with the specified filter */

static int 
DmxDevFeedStart(dmxdev_filter_t *dmxdevfilter)
{
	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_GO);

	switch (dmxdevfilter->type) {
	case DMXDEV_TYPE_SEC:
	        dmxdevfilter->feed.sec->start_filtering(dmxdevfilter->feed.sec);
		break;
	case DMXDEV_TYPE_PES:
	        dmxdevfilter->feed.ts->start_filtering(dmxdevfilter->feed.ts);
		break;
	default:
	        return -EINVAL;
	}
        return 0;
}


/* restart section feed if it has filters left associated with it, 
   otherwise release the feed */

static int 
DmxDevFeedRestart(dmxdev_filter_t *dmxdevfilter)
{
	int i;
	dmxdev_t *dmxdev=dmxdevfilter->dev;
	dvb_pid_t pid=dmxdevfilter->params.sec.pid;
	
	for (i=0; i<dmxdev->filternum; i++) 
		if (dmxdev->filter[i].state>=DMXDEV_STATE_GO &&
		    dmxdev->filter[i].type==DMXDEV_TYPE_SEC &&
		    dmxdev->filter[i].pid==pid) {
			DmxDevFeedStart(&dmxdev->filter[i]);
			return 0;
		}
	
	dmxdevfilter->dev->demux->
		release_section_feed(dmxdev->demux,
				     dmxdevfilter->feed.sec);

        return 0;
}

static int 
DmxDevFilterStop(dmxdev_filter_t *dmxdevfilter)
{
        if (dmxdevfilter->state<DMXDEV_STATE_GO) 
	        return 0;

	switch (dmxdevfilter->type) {
	case DMXDEV_TYPE_SEC:
	        if (!dmxdevfilter->feed.sec)
		        break;
	        DmxDevFeedStop(dmxdevfilter);
	        if (dmxdevfilter->filter.sec)
		        dmxdevfilter->feed.sec->
				release_filter(dmxdevfilter->feed.sec,
					       dmxdevfilter->filter.sec);
	        DmxDevFeedRestart(dmxdevfilter);
		dmxdevfilter->feed.sec=0;
		break;
	case DMXDEV_TYPE_PES:
	        if (!dmxdevfilter->feed.ts)
		        break;
	        DmxDevFeedStop(dmxdevfilter);
	        dmxdevfilter->dev->demux->
			release_ts_feed(dmxdevfilter->dev->demux,
					dmxdevfilter->feed.ts);
		dmxdevfilter->feed.ts=0;
		break;
	default:
		if (dmxdevfilter->state==DMXDEV_STATE_ALLOCATED) 
			return 0;
	        return -EINVAL;
	}
	dmxdevfilter->buffer.pwrite=dmxdevfilter->buffer.pread=0;    
        return 0;
}

static inline int 
DmxDevFilterReset(dmxdev_filter_t *dmxdevfilter)
{
	if (dmxdevfilter->state<DMXDEV_STATE_SET) 
		return 0;

	dmxdevfilter->type=DMXDEV_TYPE_NONE;
	dmxdevfilter->pid=0xffff;
	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_ALLOCATED);
        return 0;
}

static int 
DmxDevFilterStart(dmxdev_filter_t *dmxdevfilter)
{
	dmxdev_t *dmxdev=dmxdevfilter->dev;
	void *mem;
	int ret, i;

        if (dmxdevfilter->state<DMXDEV_STATE_SET) 
	        return -EINVAL;
        if (dmxdevfilter->state>=DMXDEV_STATE_GO)
	        DmxDevFilterStop(dmxdevfilter); 

	mem=dmxdevfilter->buffer.data;
	if (!mem) {
                mem=vmalloc(dmxdevfilter->buffer.size);
	        spin_lock_irq(&dmxdevfilter->dev->lock);
		dmxdevfilter->buffer.data=mem;
	        spin_unlock_irq(&dmxdevfilter->dev->lock);
                if (!dmxdevfilter->buffer.data)
                        return -ENOMEM;
	}

	switch (dmxdevfilter->type) {
	case DMXDEV_TYPE_SEC:
	{
		struct dmxSctFilterParams *para=&dmxdevfilter->params.sec;
		dmx_section_filter_t **secfilter=&dmxdevfilter->filter.sec;
		dmx_section_feed_t **secfeed=&dmxdevfilter->feed.sec;

		*secfilter=0;
		*secfeed=0;

		/* find active filter/feed with same PID */
		for (i=0; i<dmxdev->filternum; i++) 
			if (dmxdev->filter[i].state>=DMXDEV_STATE_GO &&
			    dmxdev->filter[i].pid==para->pid) {
				if (dmxdev->filter[i].type!=DMXDEV_TYPE_SEC)
					return -EBUSY;
				*secfeed=dmxdev->filter[i].feed.sec;
				break;
			}

		/* if no feed found, try to allocate new one */ 
		if (!*secfeed) {
			ret=dmxdev->demux->
				allocate_section_feed(dmxdev->demux, 
						      secfeed, 
						      DmxDevSectionCallback);
			if (ret<0) {
				printk ("could not alloc feed\n");
				return ret;
			}
			
			ret=(*secfeed)->set(*secfeed, para->pid, 32768, 0, 
					    (para->flags & DMX_CHECK_CRC) ? 1 : 0);
			
			if (ret<0) {
				printk ("could not set feed\n");
				DmxDevFeedRestart(dmxdevfilter);
				return ret;
			}
		}
	        else 
			DmxDevFeedStop(dmxdevfilter);
			
		ret=(*secfeed)->allocate_filter(*secfeed, secfilter);
		if (ret<0) {
			DmxDevFeedRestart(dmxdevfilter);
			dmxdevfilter->feed.sec->
				start_filtering(*secfeed);
			dprintk ("could not get filter\n");
			return ret;
		}

		(*secfilter)->priv=(void *) dmxdevfilter;
		memcpy(&((*secfilter)->filter_value[3]), 
		       &(para->filter.filter[1]), DMX_FILTER_SIZE-1);
		memcpy(&(*secfilter)->filter_mask[3], 
		       &para->filter.mask[1], DMX_FILTER_SIZE-1);
		(*secfilter)->filter_value[0]=para->filter.filter[0];
		(*secfilter)->filter_mask[0]=para->filter.mask[0];
		(*secfilter)->filter_mask[1]=0;
		(*secfilter)->filter_mask[2]=0;
		
	        dmxdevfilter->todo=0;
	        dmxdevfilter->feed.sec->
			start_filtering(dmxdevfilter->feed.sec);
	        DmxDevFilterTimer(dmxdevfilter);
		break;
	}

	case DMXDEV_TYPE_PES: 
	{
		struct timespec timeout = {0 };
		struct dmxPesFilterParams *para=&dmxdevfilter->params.pes;
		dmxOutput_t otype;
		int ret;
		int ts_type;
		dmx_ts_pes_t ts_pes;
		dmx_ts_feed_t **tsfeed=&dmxdevfilter->feed.ts;
		
		dmxdevfilter->feed.ts=0;
		otype=para->output;
		
		ts_pes=(dmx_ts_pes_t) para->pesType;
		
		if (ts_pes<DMX_PES_OTHER) 
			ts_type=TS_DECODER;
		else
			ts_type=0;
		
		if (otype==DMX_OUT_TS_TAP) 
			ts_type|=TS_PACKET;
		
		if (otype==DMX_OUT_TAP) 
			ts_type|=TS_PAYLOAD_ONLY|TS_PACKET;
		
		ret=dmxdev->demux->allocate_ts_feed(dmxdev->demux, 
						    tsfeed, 
						    DmxDevTSCallback);
		if (ret<0) 
			return ret;

		(*tsfeed)->priv=(void *) dmxdevfilter;
		ret=(*tsfeed)->set(*tsfeed, para->pid, 188, 32768, 0, timeout);
		if (ret<0) {
			dmxdev->demux->
				release_ts_feed(dmxdev->demux, *tsfeed);
			return ret;
		}
		if ((*tsfeed)->set_type)
			ret=(*tsfeed)->set_type(*tsfeed, ts_type, ts_pes); 
		if (ret<0) {
			dmxdev->demux->
				release_ts_feed(dmxdev->demux, *tsfeed);
			return ret;
		}
	        dmxdevfilter->feed.ts->
			start_filtering(dmxdevfilter->feed.ts);
		break;
	}
	default:
	        return -EINVAL;
	}
	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_GO);
        return 0;
}

int 
DmxDevFilterNum(dmxdev_t *dmxdev)
{
        int i, num;
        
	if (!dmxdev->filter)
	        return 0;
        down(&dmxdev->mutex);
        for (i=0, num=0; i<dmxdev->filternum; i++)
                if (dmxdev->filter[i].state==DMXDEV_STATE_FREE)
			num++;
	up(&dmxdev->mutex);
	return num;
}

int 
DmxDevFilterAlloc(dmxdev_t *dmxdev, struct file *file)
{
        int i;
        dmxdev_filter_t *dmxdevfilter;
        
	if (!dmxdev->filter)
	        return -EINVAL;
        down(&dmxdev->mutex);
        for (i=0; i<dmxdev->filternum; i++)
                if (dmxdev->filter[i].state==DMXDEV_STATE_FREE)
                        break;
        if (i==dmxdev->filternum) {
	        up(&dmxdev->mutex);
                return -EMFILE;
	}
        dmxdevfilter=&dmxdev->filter[i];
	file->private_data=dmxdevfilter;

	DmxDevBufferInit(&dmxdevfilter->buffer);
        dmxdevfilter->type=DMXDEV_TYPE_NONE;
	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_ALLOCATED);
	dmxdevfilter->feed.ts=0;
	init_timer(&dmxdevfilter->timer);

        up(&dmxdev->mutex);
	//printk("free filters = %d\n", DmxDevFilterNum(dmxdev));
        return 0;
}

int 
DmxDevFilterFree(dmxdev_t *dmxdev, struct file *file)
{
        dmxdev_filter_t *dmxdevfilter;
        
        down(&dmxdev->mutex);

        if (!(dmxdevfilter=DmxDevFile2Filter(dmxdev, file))) {
	        up(&dmxdev->mutex);
	        return -EINVAL;
        }

        DmxDevFilterStop(dmxdevfilter);
	DmxDevFilterReset(dmxdevfilter);
        
        if (dmxdevfilter->buffer.data) {
	        void *mem=dmxdevfilter->buffer.data;
		
	        spin_lock_irq(&dmxdev->lock);
		dmxdevfilter->buffer.data=0;
	        spin_unlock_irq(&dmxdev->lock);
		vfree(mem);
	}
	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_FREE);
	wake_up(&dmxdevfilter->buffer.queue);
	up(&dmxdev->mutex);
	//printk("free filters = %d\n", DmxDevFilterNum(dmxdev));
        return 0;
}


static int 
DmxDevFilterSet(dmxdev_t *dmxdev, 
                dmxdev_filter_t *dmxdevfilter, 
		struct dmxSctFilterParams *params)
{
        dprintk ("function : %s\n", __FUNCTION__);

	DmxDevFilterStop(dmxdevfilter);
        
        dmxdevfilter->type=DMXDEV_TYPE_SEC;
        dmxdevfilter->pid=params->pid;
	memcpy(&dmxdevfilter->params.sec, 
	       params, sizeof(struct dmxSctFilterParams));

	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_SET);
		
        if (params->flags&DMX_IMMEDIATE_START) 
                return DmxDevFilterStart(dmxdevfilter);

        return 0;
}

static int 
DmxDevPesFilterSet(dmxdev_t *dmxdev,
                   dmxdev_filter_t *dmxdevfilter,
                   struct dmxPesFilterParams *params)
{
	DmxDevFilterStop(dmxdevfilter);

	if (params->pesType>DMX_PES_OTHER || params->pesType<0)
	        return -EINVAL;

        dmxdevfilter->type=DMXDEV_TYPE_PES;
        dmxdevfilter->pid=params->pid;
	memcpy(&dmxdevfilter->params, params, sizeof(struct dmxPesFilterParams));

	DmxDevFilterStateSet(dmxdevfilter, DMXDEV_STATE_SET);

        if (params->flags&DMX_IMMEDIATE_START) 
                return DmxDevFilterStart(dmxdevfilter);

        return 0;
}

int 
DmxDevInit(dmxdev_t *dmxdev)
{
        int i;

	if (dmxdev->demux->open(dmxdev->demux)<0)
		return -EUSERS;
	
	dmxdev->filter=vmalloc(dmxdev->filternum*sizeof(dmxdev_filter_t));
	if (!dmxdev->filter)
	        return -ENOMEM;

	dmxdev->dvr=vmalloc(dmxdev->filternum*sizeof(dmxdev_dvr_t));
	if (!dmxdev->dvr) {
		vfree(dmxdev->filter);
		dmxdev->filter=0;
	        return -ENOMEM;
	}
        sema_init(&dmxdev->mutex, 1);
	spin_lock_init(&dmxdev->lock);
	for (i=0; i<dmxdev->filternum; i++) {
                dmxdev->filter[i].dev=dmxdev;
                dmxdev->filter[i].buffer.data=0;
	        DmxDevFilterStateSet(&dmxdev->filter[i], DMXDEV_STATE_FREE);
                dmxdev->dvr[i].dev=dmxdev;
                dmxdev->dvr[i].buffer.data=0;
	        DmxDevFilterStateSet(&dmxdev->filter[i], DMXDEV_STATE_FREE);
	        DmxDevDVRStateSet(&dmxdev->dvr[i], DMXDEV_STATE_FREE);
	}
	DmxDevBufferInit(&dmxdev->dvr_buffer);
	MOD_INC_USE_COUNT;
	return 0;
}

void 
DmxDevRelease(dmxdev_t *dmxdev)
{
	if (dmxdev->filter) {
	        vfree(dmxdev->filter);
		dmxdev->filter=0;
	}
	if (dmxdev->dvr) {
	        vfree(dmxdev->dvr);
		dmxdev->dvr=0;
	}
        dmxdev->demux->close(dmxdev->demux);
	MOD_DEC_USE_COUNT;
}

static ssize_t 
DmxDevReadSec(dmxdev_filter_t *dfil, struct file *file, 
	      char *buf, size_t count, loff_t *ppos)
{
        int result, hcount;
	int done=0;
	
	if (dfil->todo<=0) {
	        hcount=3+dfil->todo;
	        if (hcount>count)
		        hcount=count;
		result=DmxDevBufferRead(&dfil->buffer, file->f_flags&O_NONBLOCK, 
					buf, hcount, ppos);
		if (result<0) {
			dfil->todo=0;
		        return result;
		}
		if (copy_from_user(dfil->secheader-dfil->todo, buf, result)) 
		        return -EFAULT;
		buf+=result;
		done=result;
		count-=result;
		dfil->todo-=result;
		if (dfil->todo>-3)
		        return done;
		dfil->todo=((dfil->secheader[1]<<8)|dfil->secheader[2])&0xfff;
		if (!count)
		        return done;
	}
	if (count>dfil->todo)
	        count=dfil->todo;
        result=DmxDevBufferRead(&dfil->buffer, file->f_flags&O_NONBLOCK, 
				buf, count, ppos);
	if (result<0)
	        return result;
	dfil->todo-=result;
	return (result+done);
}


ssize_t 
DmxDevRead(dmxdev_t *dmxdev, struct file *file, 
	   char *buf, size_t count, loff_t *ppos)
{
        dmxdev_filter_t *dmxdevfilter=DmxDevFile2Filter(dmxdev, file);
	int ret=0;

        down(&dmxdev->mutex);
	if (dmxdevfilter->type==DMXDEV_TYPE_SEC)
	        ret=DmxDevReadSec(dmxdevfilter, file, buf, count, ppos);
	else
	        ret=DmxDevBufferRead(&dmxdevfilter->buffer, 
				     file->f_flags&O_NONBLOCK, 
				     buf, count, ppos);
        up(&dmxdev->mutex);
	return ret;
}


int DmxDevIoctl(dmxdev_t *dmxdev, struct file *file, 
		unsigned int cmd, unsigned long arg)
{
        void *parg=(void *)arg;
	int ret=0;

        dmxdev_filter_t *dmxdevfilter=DmxDevFile2Filter(dmxdev, file);
  
	if (!dmxdevfilter)
	        return -EINVAL;

        down(&dmxdev->mutex);
	switch (cmd) {
	case DMX_START: 
	        if (dmxdevfilter->state<DMXDEV_STATE_SET)
		        ret=-EINVAL;
		else
		        ret=DmxDevFilterStart(dmxdevfilter);
		break;

	case DMX_STOP: 
		ret=DmxDevFilterStop(dmxdevfilter);
		break;

	case DMX_SET_FILTER: 
	{
	        struct dmxSctFilterParams params;

	        if (copy_from_user(&params, parg, sizeof(params)))
			
		        ret=-EFAULT;
		else
		        ret=DmxDevFilterSet(dmxdev, dmxdevfilter, &params);
		break;
	}

	case DMX_SET_PES_FILTER: 
	{
	        struct dmxPesFilterParams params;
		
		if (copy_from_user(&params, parg, sizeof(params)))
		        ret=-EFAULT;
		else
			ret=DmxDevPesFilterSet(dmxdev, dmxdevfilter, &params);
		break;
	}

	case DMX_SET_BUFFER_SIZE: 
	        ret=DmxDevSetBufferSize(dmxdevfilter, arg);
		break;
        
        case DMX_GET_EVENT: 
	        break;
		
        case DMX_GET_PES_PIDS: 
	{
	        dvb_pid_t pids[5];

		if (!dmxdev->demux->get_pes_pids) {
		        ret=-EINVAL;
			break;
		}
		dmxdev->demux->get_pes_pids(dmxdev->demux, pids);
	        if (copy_to_user(parg, pids, 5*sizeof(dvb_pid_t)))
		        ret=-EFAULT;
	        break;
	}	

	default:
	        ret=-EINVAL;
	}
        up(&dmxdev->mutex);
	return ret;
}

unsigned int 
DmxDevPoll(dmxdev_t *dmxdev, struct file *file, poll_table * wait)
{
        dmxdev_filter_t *dmxdevfilter=DmxDevFile2Filter(dmxdev, file);

	if (!dmxdevfilter)
	        return -EINVAL;

	if (dmxdevfilter->state==DMXDEV_STATE_FREE)
	        return 0;

	if (dmxdevfilter->buffer.pread!=dmxdevfilter->buffer.pwrite ||
	    dmxdevfilter->buffer.error)
	        return (POLLIN | POLLRDNORM | POLLPRI);

	if (dmxdevfilter->state!=DMXDEV_STATE_GO)
	        return 0;

	poll_wait(file, &dmxdevfilter->buffer.queue, wait);
                
	if (dmxdevfilter->state==DMXDEV_STATE_FREE)
	        return 0;

	if (dmxdevfilter->buffer.pread!=dmxdevfilter->buffer.pwrite  ||
	    dmxdevfilter->buffer.error)
	        return (POLLIN | POLLRDNORM | POLLPRI);

	return 0;
}

int DmxDevDVRIoctl(dmxdev_t *dmxdev, struct file *file, 
		   unsigned int cmd, unsigned long arg)
{
        //void *parg=(void *)arg;
	int ret=0;

        down(&dmxdev->mutex);
	switch (cmd) {
	case DMX_SET_BUFFER_SIZE: 
		// FIXME: implement
	        ret=0;
		break;
		
	default:
	        ret=-EINVAL;
	}
        up(&dmxdev->mutex);
	return ret;
}

unsigned int 
DmxDevDVRPoll(dmxdev_t *dmxdev, struct file *file, poll_table * wait)
{
        if ((file->f_flags&O_ACCMODE)==O_RDONLY) {
		if (dmxdev->dvr_buffer.pread!=dmxdev->dvr_buffer.pwrite)
			return (POLLIN | POLLRDNORM | POLLPRI);
		
		poll_wait(file, &dmxdev->dvr_buffer.queue, wait);
		
		if (dmxdev->dvr_buffer.pread!=dmxdev->dvr_buffer.pwrite)
			return (POLLIN | POLLRDNORM | POLLPRI);
		
		return 0;
	} else 
	        return (POLLOUT | POLLWRNORM | POLLPRI);
}


#ifdef MODULE
#ifdef EXPORT_SYMTAB
EXPORT_SYMBOL(DmxDevInit);
EXPORT_SYMBOL(DmxDevRelease);

EXPORT_SYMBOL(DmxDevDVROpen);
EXPORT_SYMBOL(DmxDevDVRClose);
EXPORT_SYMBOL(DmxDevDVRRead);
EXPORT_SYMBOL(DmxDevDVRWrite);
EXPORT_SYMBOL(DmxDevDVRIoctl);
EXPORT_SYMBOL(DmxDevDVRPoll);

EXPORT_SYMBOL(DmxDevFilterAlloc);
EXPORT_SYMBOL(DmxDevFilterFree);
EXPORT_SYMBOL(DmxDevRead);
EXPORT_SYMBOL(DmxDevIoctl);
EXPORT_SYMBOL(DmxDevPoll);
#endif
#endif

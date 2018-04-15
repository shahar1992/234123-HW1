/*
 *   Copyright (c) International Business Machines Corp., 2000-2002
 *   Portions Copyright (c) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or 
 *   (at your option) any later version.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software 
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 *	jfs_logmgr.c: log manager
 *
 * for related information, see transaction manager (jfs_txnmgr.c), and
 * recovery manager (jfs_logredo.c).
 *
 * note: for detail, RTFS.
 *
 *	log buffer manager:
 * special purpose buffer manager supporting log i/o requirements.
 * per log serial pageout of logpage
 * queuing i/o requests and redrive i/o at iodone
 * maintain current logpage buffer
 * no caching since append only
 * appropriate jfs buffer cache buffers as needed
 *
 *	group commit:
 * transactions which wrote COMMIT records in the same in-memory
 * log page during the pageout of previous/current log page(s) are
 * committed together by the pageout of the page.
 *
 *	TBD lazy commit:
 * transactions are committed asynchronously when the log page
 * containing it COMMIT is paged out when it becomes full;
 *
 *	serialization:
 * . a per log lock serialize log write.
 * . a per log lock serialize group commit.
 * . a per log lock serialize log open/close;
 *
 *	TBD log integrity:
 * careful-write (ping-pong) of last logpage to recover from crash
 * in overwrite.
 * detection of split (out-of-order) write of physical sectors
 * of last logpage via timestamp at end of each sector
 * with its mirror data array at trailer).
 *
 *	alternatives:
 * lsn - 64-bit monotonically increasing integer vs
 * 32-bit lspn and page eor.
 */

#include <linux/fs.h>
#include <linux/locks.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <linux/smp_lock.h>
#include <linux/completion.h>
#include "jfs_incore.h"
#include "jfs_filsys.h"
#include "jfs_metapage.h"
#include "jfs_txnmgr.h"
#include "jfs_debug.h"


/*
 * lbuf's ready to be redriven.  Protected by log_redrive_lock (jfsIO thread)
 */
static lbuf_t *log_redrive_list;
static spinlock_t log_redrive_lock = SPIN_LOCK_UNLOCKED;
DECLARE_WAIT_QUEUE_HEAD(jfs_IO_thread_wait);


/*
 *	log read/write serialization (per log)
 */
#define LOG_LOCK_INIT(log)	init_MUTEX(&(log)->loglock)
#define LOG_LOCK(log)		down(&((log)->loglock))
#define LOG_UNLOCK(log)		up(&((log)->loglock))


/*
 *	log group commit serialization (per log)
 */

#define LOGGC_LOCK_INIT(log)	spin_lock_init(&(log)->gclock)
#define LOGGC_LOCK(log)		spin_lock_irq(&(log)->gclock)
#define LOGGC_UNLOCK(log)	spin_unlock_irq(&(log)->gclock)
#define LOGGC_WAKEUP(tblk)	wake_up(&(tblk)->gcwait)

/*
 *	log sync serialization (per log)
 */
#define	LOGSYNC_DELTA(logsize)		min((logsize)/8, 128*LOGPSIZE)
#define	LOGSYNC_BARRIER(logsize)	((logsize)/4)
/*
#define	LOGSYNC_DELTA(logsize)		min((logsize)/4, 256*LOGPSIZE)
#define	LOGSYNC_BARRIER(logsize)	((logsize)/2)
*/


/*
 *	log buffer cache synchronization
 */
static spinlock_t jfsLCacheLock = SPIN_LOCK_UNLOCKED;

#define	LCACHE_LOCK(flags)	spin_lock_irqsave(&jfsLCacheLock, flags)
#define	LCACHE_UNLOCK(flags)	spin_unlock_irqrestore(&jfsLCacheLock, flags)

/*
 * See __SLEEP_COND in jfs_locks.h
 */
#define LCACHE_SLEEP_COND(wq, cond, flags)	\
do {						\
	if (cond)				\
		break;				\
	__SLEEP_COND(wq, cond, LCACHE_LOCK(flags), LCACHE_UNLOCK(flags)); \
} while (0)

#define	LCACHE_WAKEUP(event)	wake_up(event)


/*
 *	lbuf buffer cache (lCache) control
 */
/* log buffer manager pageout control (cumulative, inclusive) */
#define	lbmREAD		0x0001
#define	lbmWRITE	0x0002	/* enqueue at tail of write queue;
				 * init pageout if at head of queue;
				 */
#define	lbmRELEASE	0x0004	/* remove from write queue
				 * at completion of pageout;
				 * do not free/recycle it yet:
				 * caller will free it;
				 */
#define	lbmSYNC		0x0008	/* do not return to freelist
				 * when removed from write queue;
				 */
#define lbmFREE		0x0010	/* return to freelist
				 * at completion of pageout;
				 * the buffer may be recycled;
				 */
#define	lbmDONE		0x0020
#define	lbmERROR	0x0040
#define lbmGC		0x0080	/* lbmIODone to perform post-GC processing
				 * of log page
				 */
#define lbmDIRECT	0x0100

/*
 * external references
 */
extern void txLazyUnlock(tblock_t * tblk);
extern int jfs_stop_threads;
extern struct completion jfsIOwait;

/*
 * forward references
 */
static int lmWriteRecord(log_t * log, tblock_t * tblk, lrd_t * lrd,
			 tlock_t * tlck);

static int lmNextPage(log_t * log);
static int lmLogFileSystem(log_t * log, char *uuid, int activate);
static int lmLogInit(log_t * log);
static int lmLogShutdown(log_t * log);

static int lbmLogInit(log_t * log);
static void lbmLogShutdown(log_t * log);
static lbuf_t *lbmAllocate(log_t * log, int);
static void lbmFree(lbuf_t * bp);
static void lbmfree(lbuf_t * bp);
static int lbmRead(log_t * log, int pn, lbuf_t ** bpp);
static void lbmWrite(log_t * log, lbuf_t * bp, int flag, int cant_block);
static void lbmDirectWrite(log_t * log, lbuf_t * bp, int flag);
static int lbmIOWait(lbuf_t * bp, int flag);
static void lbmIODone(struct buffer_head *bh, int);

void lbmStartIO(lbuf_t * bp);
void lmGCwrite(log_t * log, int cant_block);


/*
 *	statistics
 */
#ifdef CONFIG_JFS_STATISTICS
struct lmStat {
	uint commit;		/* # of commit */
	uint pagedone;		/* # of page written */
	uint submitted;		/* # of pages submitted */
} lmStat;
#endif


/*
 * NAME:	lmLog()
 *
 * FUNCTION:	write a log record;
 *
 * PARAMETER:
 *
 * RETURN:	lsn - offset to the next log record to write (end-of-log);
 *		-1  - error;
 *
 * note: todo: log error handler
 */
int lmLog(log_t * log, tblock_t * tblk, lrd_t * lrd, tlock_t * tlck)
{
	int lsn;
	int diffp, difft;
	metapage_t *mp = NULL;

	jFYI(1, ("lmLog: log:0x%p tblk:0x%p, lrd:0x%p tlck:0x%p\n",
		 log, tblk, lrd, tlck));

	LOG_LOCK(log);

	/* log by (out-of-transaction) JFS ? */
	if (tblk == NULL)
		goto writeRecord;

	/* log from page ? */
	if (tlck == NULL ||
	    tlck->type & tlckBTROOT || (mp = tlck->mp) == NULL)
		goto writeRecord;

	/*
	 *      initialize/update page/transaction recovery lsn
	 */
	lsn = log->lsn;

	LOGSYNC_LOCK(log);

	/*
	 * initialize page lsn if first log write of the page
	 */
	if (mp->lsn == 0) {
		mp->log = log;
		mp->lsn = lsn;
		log->count++;

		/* insert page at tail of logsynclist */
		list_add_tail(&mp->synclist, &log->synclist);
	}

	/*
	 *      initialize/update lsn of tblock of the page
	 *
	 * transaction inherits oldest lsn of pages associated
	 * with allocation/deallocation of resources (their
	 * log records are used to reconstruct allocation map
	 * at recovery time: inode for inode allocation map,
	 * B+-tree index of extent descriptors for block
	 * allocation map);
	 * allocation map pages inherit transaction lsn at
	 * commit time to allow forwarding log syncpt past log
	 * records associated with allocation/deallocation of
	 * resources only after persistent map of these map pages
	 * have been updated and propagated to home.
	 */
	/*
	 * initialize transaction lsn:
	 */
	if (tblk->lsn == 0) {
		/* inherit lsn of its first page logged */
		tblk->lsn = mp->lsn;
		log->count++;

		/* insert tblock after the page on logsynclist */
		list_add(&tblk->synclist, &mp->synclist);
	}
	/*
	 * update transaction lsn:
	 */
	else {
		/* inherit oldest/smallest lsn of page */
		logdiff(diffp, mp->lsn, log);
		logdiff(difft, tblk->lsn, log);
		if (diffp < difft) {
			/* update tblock lsn with page lsn */
			tblk->lsn = mp->lsn;

			/* move tblock after page on logsynclist */
			list_del(&tblk->synclist);
			list_add(&tblk->synclist, &mp->synclist);
		}
	}

	LOGSYNC_UNLOCK(log);

	/*
	 *      write the log record
	 */
      writeRecord:
	lsn = lmWriteRecord(log, tblk, lrd, tlck);

	/*
	 * forward log syncpt if log reached next syncpt trigger
	 */
	logdiff(diffp, lsn, log);
	if (diffp >= log->nextsync)
		lsn = lmLogSync(log, 0);

	/* update end-of-log lsn */
	log->lsn = lsn;

	LOG_UNLOCK(log);

	/* return end-of-log address */
	return lsn;
}


/*
 * NAME:	lmWriteRecord()
 *
 * FUNCTION:	move the log record to current log page
 *
 * PARAMETER:	cd	- commit descriptor
 *
 * RETURN:	end-of-log address
 *			
 * serialization: LOG_LOCK() held on entry/exit
 */
static int
lmWriteRecord(log_t * log, tblock_t * tblk, lrd_t * lrd, tlock_t * tlck)
{
	int lsn = 0;		/* end-of-log address */
	lbuf_t *bp;		/* dst log page buffer */
	logpage_t *lp;		/* dst log page */
	caddr_t dst;		/* destination address in log page */
	int dstoffset;		/* end-of-log offset in log page */
	int freespace;		/* free space in log page */
	caddr_t p;		/* src meta-data page */
	caddr_t src;
	int srclen;
	int nbytes;		/* number of bytes to move */
	int i;
	int len;
	linelock_t *linelock;
	lv_t *lv;
	lvd_t *lvd;
	int l2linesize;

	len = 0;

	/* retrieve destination log page to write */
	bp = (lbuf_t *) log->bp;
	lp = (logpage_t *) bp->l_ldata;
	dstoffset = log->eor;

	/* any log data to write ? */
	if (tlck == NULL)
		goto moveLrd;

	/*
	 *      move log record data
	 */
	/* retrieve source meta-data page to log */
	if (tlck->flag & tlckPAGELOCK) {
		p = (caddr_t) (tlck->mp->data);
		linelock = (linelock_t *) & tlck->lock;
	}
	/* retrieve source in-memory inode to log */
	else if (tlck->flag & tlckINODELOCK) {
		if (tlck->type & tlckDTREE)
			p = (caddr_t) &JFS_IP(tlck->ip)->i_dtroot;
		else
			p = (caddr_t) &JFS_IP(tlck->ip)->i_xtroot;
		linelock = (linelock_t *) & tlck->lock;
	}
#ifdef	_JFS_WIP
	else if (tlck->flag & tlckINLINELOCK) {

		inlinelock = (inlinelock_t *) & tlck;
		p = (caddr_t) & inlinelock->pxd;
		linelock = (linelock_t *) & tlck;
	}
#endif				/* _JFS_WIP */
	else {
		jERROR(2, ("lmWriteRecord: UFO tlck:0x%p\n", tlck));
		return 0;	/* Probably should trap */
	}
	l2linesize = linelock->l2linesize;

      moveData:
	ASSERT(linelock->index <= linelock->maxcnt);

	lv = (lv_t *) & linelock->lv;
	for (i = 0; i < linelock->index; i++, lv++) {
		if (lv->length == 0)
			continue;

		/* is page full ? */
		if (dstoffset >= LOGPSIZE - LOGPTLRSIZE) {
			/* page become full: move on to next page */
			lmNextPage(log);

			bp = log->bp;
			lp = (logpage_t *) bp->l_ldata;
			dstoffset = LOGPHDRSIZE;
		}

		/*
		 * move log vector data
		 */
		src = (u8 *) p + (lv->offset << l2linesize);
		srclen = lv->length << l2linesize;
		len += srclen;
		while (srclen > 0) {
			freespace = (LOGPSIZE - LOGPTLRSIZE) - dstoffset;
			nbytes = min(freespace, srclen);
			dst = (caddr_t) lp + dstoffset;
			memcpy(dst, src, nbytes);
			dstoffset += nbytes;

			/* is page not full ? */
			if (dstoffset < LOGPSIZE - LOGPTLRSIZE)
				break;

			/* page become full: move on to next page */
			lmNextPage(log);

			bp = (lbuf_t *) log->bp;
			lp = (logpage_t *) bp->l_ldata;
			dstoffset = LOGPHDRSIZE;

			srclen -= nbytes;
			src += nbytes;
		}

		/*
		 * move log vector descriptor
		 */
		len += 4;
		lvd = (lvd_t *) ((caddr_t) lp + dstoffset);
		lvd->offset = cpu_to_le16(lv->offset);
		lvd->length = cpu_to_le16(lv->length);
		dstoffset += 4;
		jFYI(1,
		     ("lmWriteRecord: lv offset:%d length:%d\n",
		      lv->offset, lv->length));
	}

	if ((i = linelock->next)) {
		linelock = (linelock_t *) lid_to_tlock(i);
		goto moveData;
	}

	/*
	 *      move log record descriptor
	 */
      moveLrd:
	lrd->length = cpu_to_le16(len);

	src = (caddr_t) lrd;
	srclen = LOGRDSIZE;

	while (srclen > 0) {
		freespace = (LOGPSIZE - LOGPTLRSIZE) - dstoffset;
		nbytes = min(freespace, srclen);
		dst = (caddr_t) lp + dstoffset;
		memcpy(dst, src, nbytes);

		dstoffset += nbytes;
		srclen -= nbytes;

		/* are there more to move than freespace of page ? */
		if (srclen)
			goto pageFull;

		/*
		 * end of log record descriptor
		 */

		/* update last log record eor */
		log->eor = dstoffset;
		bp->l_eor = dstoffset;
		lsn = (log->page << L2LOGPSIZE) + dstoffset;

		if (lrd->type & cpu_to_le16(LOG_COMMIT)) {
			tblk->clsn = lsn;
			jFYI(1,
			     ("wr: tclsn:0x%x, beor:0x%x\n", tblk->clsn,
			      bp->l_eor));

			INCREMENT(lmStat.commit);	/* # of commit */

			/*
			 * enqueue tblock for group commit:
			 *
			 * enqueue tblock of non-trivial/synchronous COMMIT
			 * at tail of group commit queue
			 * (trivial/asynchronous COMMITs are ignored by
			 * group commit.)
			 */
			LOGGC_LOCK(log);

			/* init tblock gc state */
			tblk->flag = tblkGC_QUEUE;
			tblk->bp = log->bp;
			tblk->pn = log->page;
			tblk->eor = log->eor;
			init_waitqueue_head(&tblk->gcwait);

			/* enqueue transaction to commit queue */
			tblk->cqnext = NULL;
			if (log->cqueue.head) {
				log->cqueue.tail->cqnext = tblk;
				log->cqueue.tail = tblk;
			} else
				log->cqueue.head = log->cqueue.tail = tblk;

			LOGGC_UNLOCK(log);
		}

		jFYI(1,
		     ("lmWriteRecord: lrd:0x%04x bp:0x%p pn:%d eor:0x%x\n",
		      le16_to_cpu(lrd->type), log->bp, log->page,
		      dstoffset));

		/* page not full ? */
		if (dstoffset < LOGPSIZE - LOGPTLRSIZE)
			return lsn;

	      pageFull:
		/* page become full: move on to next page */
		lmNextPage(log);

		bp = (lbuf_t *) log->bp;
		lp = (logpage_t *) bp->l_ldata;
		dstoffset = LOGPHDRSIZE;
		src += nbytes;
	}

	return lsn;
}


/*
 * NAME:	lmNextPage()
 *
 * FUNCTION:	write current page and allocate next page.
 *
 * PARAMETER:	log
 *
 * RETURN:	0
 *			
 * serialization: LOG_LOCK() held on entry/exit
 */
static int lmNextPage(log_t * log)
{
	logpage_t *lp;
	int lspn;		/* log sequence page number */
	int pn;			/* current page number */
	lbuf_t *bp;
	lbuf_t *nextbp;
	tblock_t *tblk;

	jFYI(1, ("lmNextPage\n"));

	/* get current log page number and log sequence page number */
	pn = log->page;
	bp = log->bp;
	lp = (logpage_t *) bp->l_ldata;
	lspn = le32_to_cpu(lp->h.page);

	LOGGC_LOCK(log);

	/*
	 *      write or queue the full page at the tail of write queue
	 */
	/* get the tail tblk on commit queue */
	tblk = log->cqueue.tail;

	/* every tblk who has COMMIT record on the current page,
	 * and has not been committed, must be on commit queue
	 * since tblk is queued at commit queueu at the time
	 * of writing its COMMIT record on the page before
	 * page becomes full (even though the tblk thread
	 * who wrote COMMIT record may have been suspended
	 * currently);
	 */

	/* is page bound with outstanding tail tblk ? */
	if (tblk && tblk->pn == pn) {
		/* mark tblk for end-of-page */
		tblk->flag |= tblkGC_EOP;

		/* if page is not already on write queue,
		 * just enqueue (no lbmWRITE to prevent redrive)
		 * buffer to wqueue to ensure correct serial order
		 * of the pages since log pages will be added
		 * continuously (tblk bound with the page hasn't
		 * got around to init write of the page, either
		 * preempted or the page got filled by its COMMIT
		 * record);
		 * pages with COMMIT are paged out explicitly by
		 * tblk in lmGroupCommit();
		 */
		if (bp->l_wqnext == NULL) {
			/* bp->l_ceor = bp->l_eor; */
			/* lp->h.eor = lp->t.eor = bp->l_ceor; */
			lbmWrite(log, bp, 0, 0);
		}
	}
	/* page is not bound with outstanding tblk:
	 * init write or mark it to be redriven (lbmWRITE)
	 */
	else {
		/* finalize the page */
		bp->l_ceor = bp->l_eor;
		lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_ceor);
		lbmWrite(log, bp, lbmWRITE | lbmRELEASE | lbmFREE, 0);
	}
	LOGGC_UNLOCK(log);

	/*
	 *      allocate/initialize next page
	 */
	/* if log wraps, the first data page of log is 2
	 * (0 never used, 1 is superblock).
	 */
	log->page = (pn == log->size - 1) ? 2 : pn + 1;
	log->eor = LOGPHDRSIZE;	/* ? valid page empty/full at logRedo() */

	/* allocate/initialize next log page buffer */
	nextbp = lbmAllocate(log, log->page);
	nextbp->l_eor = log->eor;
	log->bp = nextbp;

	/* initialize next log page */
	lp = (logpage_t *) nextbp->l_ldata;
	lp->h.page = lp->t.page = cpu_to_le32(lspn + 1);
	lp->h.eor = lp->t.eor = cpu_to_le16(LOGPHDRSIZE);

	jFYI(1, ("lmNextPage done\n"));
	return 0;
}


/*
 * NAME:	lmGroupCommit()
 *
 * FUNCTION:	group commit
 *	initiate pageout of the pages with COMMIT in the order of
 *	page number - redrive pageout of the page at the head of
 *	pageout queue until full page has been written.
 *
 * RETURN:	
 *
 * NOTE:
 *	LOGGC_LOCK serializes log group commit queue, and
 *	transaction blocks on the commit queue.
 *	N.B. LOG_LOCK is NOT held during lmGroupCommit().
 */
int lmGroupCommit(log_t * log, tblock_t * tblk)
{
	int rc = 0;

	LOGGC_LOCK(log);

	/* group committed already ? */
	if (tblk->flag & tblkGC_COMMITTED) {
		if (tblk->flag & tblkGC_ERROR)
			rc = EIO;

		LOGGC_UNLOCK(log);
		return rc;
	}
	jFYI(1,
	     ("lmGroup Commit: tblk = 0x%p, gcrtc = %d\n", tblk,
	      log->gcrtc));

	/*
	 * group commit pageout in progress
	 */
	if ((!(log->cflag & logGC_PAGEOUT)) && log->cqueue.head) {
		/*
		 * only transaction in the commit queue:
		 *
		 * start one-transaction group commit as
		 * its group leader.
		 */
		log->cflag |= logGC_PAGEOUT;

		lmGCwrite(log, 0);
	}
	/* lmGCwrite gives up LOGGC_LOCK, check again */

	if (tblk->flag & tblkGC_COMMITTED) {
		if (tblk->flag & tblkGC_ERROR)
			rc = EIO;

		LOGGC_UNLOCK(log);
		return rc;
	}

	/* upcount transaction waiting for completion
	 */
	log->gcrtc++;

	if (tblk->xflag & COMMIT_LAZY) {
		tblk->flag |= tblkGC_LAZY;
		LOGGC_UNLOCK(log);
		return 0;
	}
	tblk->flag |= tblkGC_READY;

	__SLEEP_COND(tblk->gcwait, (tblk->flag & tblkGC_COMMITTED),
		     LOGGC_LOCK(log), LOGGC_UNLOCK(log));

	/* removed from commit queue */
	if (tblk->flag & tblkGC_ERROR)
		rc = EIO;

	LOGGC_UNLOCK(log);
	return rc;
}

/*
 * NAME:	lmGCwrite()
 *
 * FUNCTION:	group commit write
 *	initiate write of log page, building a group of all transactions
 *	with commit records on that page.
 *
 * RETURN:	None
 *
 * NOTE:
 *	LOGGC_LOCK must be held by caller.
 *	N.B. LOG_LOCK is NOT held during lmGroupCommit().
 */
void lmGCwrite(log_t * log, int cant_write)
{
	lbuf_t *bp;
	logpage_t *lp;
	int gcpn;		/* group commit page number */
	tblock_t *tblk;
	tblock_t *xtblk;

	/*
	 * build the commit group of a log page
	 *
	 * scan commit queue and make a commit group of all
	 * transactions with COMMIT records on the same log page.
	 */
	/* get the head tblk on the commit queue */
	tblk = xtblk = log->cqueue.head;
	gcpn = tblk->pn;

	while (tblk && tblk->pn == gcpn) {
		xtblk = tblk;

		/* state transition: (QUEUE, READY) -> COMMIT */
		tblk->flag |= tblkGC_COMMIT;
		tblk = tblk->cqnext;
	}
	tblk = xtblk;		/* last tblk of the page */

	/*
	 * pageout to commit transactions on the log page.
	 */
	bp = (lbuf_t *) tblk->bp;
	lp = (logpage_t *) bp->l_ldata;
	/* is page already full ? */
	if (tblk->flag & tblkGC_EOP) {
		/* mark page to free at end of group commit of the page */
		tblk->flag &= ~tblkGC_EOP;
		tblk->flag |= tblkGC_FREE;
		bp->l_ceor = bp->l_eor;
		lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_ceor);
		jEVENT(0,
		       ("gc: tclsn:0x%x, bceor:0x%x\n", tblk->clsn,
			bp->l_ceor));
		lbmWrite(log, bp, lbmWRITE | lbmRELEASE | lbmGC,
			 cant_write);
	}
	/* page is not yet full */
	else {
		bp->l_ceor = tblk->eor;	/* ? bp->l_ceor = bp->l_eor; */
		lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_ceor);
		jEVENT(0,
		       ("gc: tclsn:0x%x, bceor:0x%x\n", tblk->clsn,
			bp->l_ceor));
		lbmWrite(log, bp, lbmWRITE | lbmGC, cant_write);
	}
}

/*
 * NAME:	lmPostGC()
 *
 * FUNCTION:	group commit post-processing
 *	Processes transactions after their commit records have been written
 *	to disk, redriving log I/O if necessary.
 *
 * RETURN:	None
 *
 * NOTE:
 *	This routine is called a interrupt time by lbmIODone
 */
void lmPostGC(lbuf_t * bp)
{
	unsigned long flags;
	log_t *log = bp->l_log;
	logpage_t *lp;
	tblock_t *tblk;

	//LOGGC_LOCK(log);
	spin_lock_irqsave(&log->gclock, flags);
	/*
	 * current pageout of group commit completed.
	 *
	 * remove/wakeup transactions from commit queue who were
	 * group committed with the current log page
	 */
	while ((tblk = log->cqueue.head) && (tblk->flag & tblkGC_COMMIT)) {
		/* if transaction was marked GC_COMMIT then
		 * it has been shipped in the current pageout
		 * and made it to disk - it is committed.
		 */

		if (bp->l_flag & lbmERROR)
			tblk->flag |= tblkGC_ERROR;

		/* remove it from the commit queue */
		log->cqueue.head = tblk->cqnext;
		if (log->cqueue.head == NULL)
			log->cqueue.tail = NULL;
		tblk->flag &= ~tblkGC_QUEUE;
		tblk->cqnext = 0;

		jEVENT(0,
		       ("lmPostGC: tblk = 0x%p, flag = 0x%x\n", tblk,
			tblk->flag));

		if (!(tblk->xflag & COMMIT_FORCE))
			/*
			 * Hand tblk over to lazy commit thread
			 */
			txLazyUnlock(tblk);
		else {
			/* state transition: COMMIT -> COMMITTED */
			tblk->flag |= tblkGC_COMMITTED;

			if (tblk->flag & tblkGC_READY) {
				log->gcrtc--;
				LOGGC_WAKEUP(tblk);
			}
		}

		/* was page full before pageout ?
		 * (and this is the last tblk bound with the page)
		 */
		if (tblk->flag & tblkGC_FREE)
			lbmFree(bp);
		/* did page become full after pageout ?
		 * (and this is the last tblk bound with the page)
		 */
		else if (tblk->flag & tblkGC_EOP) {
			/* finalize the page */
			lp = (logpage_t *) bp->l_ldata;
			bp->l_ceor = bp->l_eor;
			lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_eor);
			jEVENT(0, ("lmPostGC: calling lbmWrite\n"));
			lbmWrite(log, bp, lbmWRITE | lbmRELEASE | lbmFREE,
				 1);
		}

	}

	/* are there any transactions who have entered lnGroupCommit()
	 * (whose COMMITs are after that of the last log page written.
	 * They are waiting for new group commit (above at (SLEEP 1)):
	 * select the latest ready transaction as new group leader and
	 * wake her up to lead her group.
	 */
	if ((log->gcrtc > 0) && log->cqueue.head)
		/*
		 * Call lmGCwrite with new group leader
		 */
		lmGCwrite(log, 1);

	/* no transaction are ready yet (transactions are only just
	 * queued (GC_QUEUE) and not entered for group commit yet).
	 * let the first transaction entering group commit
	 * will elect hetself as new group leader.
	 */
	else
		log->cflag &= ~logGC_PAGEOUT;

	//LOGGC_UNLOCK(log);
	spin_unlock_irqrestore(&log->gclock, flags);
	return;
}

/*
 * NAME:	lmLogSync()
 *
 * FUNCTION:	write log SYNCPT record for specified log
 *	if new sync address is available
 *	(normally the case if sync() is executed by back-ground
 *	process).
 *	if not, explicitly run jfs_blogsync() to initiate
 *	getting of new sync address.
 *	calculate new value of i_nextsync which determines when
 *	this code is called again.
 *
 *	this is called only from lmLog().
 *
 * PARAMETER:	ip	- pointer to logs inode.
 *
 * RETURN:	0
 *			
 * serialization: LOG_LOCK() held on entry/exit
 */
int lmLogSync(log_t * log, int nosyncwait)
{
	int logsize;
	int written;		/* written since last syncpt */
	int free;		/* free space left available */
	int delta;		/* additional delta to write normally */
	int more;		/* additional write granted */
	lrd_t lrd;
	int lsn;
	struct logsyncblk *lp;

	/*
	 *      forward syncpt
	 */
	/* if last sync is same as last syncpt,
	 * invoke sync point forward processing to update sync.
	 */

	if (log->sync == log->syncpt) {
		LOGSYNC_LOCK(log);
		/* ToDo: push dirty metapages out to disk */
//              bmLogSync(log);

		if (list_empty(&log->synclist))
			log->sync = log->lsn;
		else {
			lp = list_entry(log->synclist.next,
					struct logsyncblk, synclist);
			log->sync = lp->lsn;
		}
		LOGSYNC_UNLOCK(log);

	}

	/* if sync is different from last syncpt,
	 * write a SYNCPT record with syncpt = sync.
	 * reset syncpt = sync
	 */
	if (log->sync != log->syncpt) {
		struct jfs_sb_info	*sbi = JFS_SBI(log->sb);
		/*
		 * We need to make sure all of the "written" metapages
		 * actually make it to disk
		 */
		fsync_inode_data_buffers(sbi->ipbmap);
		fsync_inode_data_buffers(sbi->ipimap);
		fsync_inode_data_buffers(sbi->direct_inode);

		lrd.logtid = 0;
		lrd.backchain = 0;
		lrd.type = cpu_to_le16(LOG_SYNCPT);
		lrd.length = 0;
		lrd.log.syncpt.sync = cpu_to_le32(log->sync);
		lsn = lmWriteRecord(log, NULL, &lrd, NULL);

		log->syncpt = log->sync;
	} else
		lsn = log->lsn;

	/*
	 *      setup next syncpt trigger (SWAG)
	 */
	logsize = log->logsize;

	logdiff(written, lsn, log);
	free = logsize - written;
	delta = LOGSYNC_DELTA(logsize);
	more = min(free / 2, delta);
	if (more < 2 * LOGPSIZE) {
		jEVENT(1,
		       ("\n ... Log Wrap ... Log Wrap ... Log Wrap ...\n\n"));
		/*
		 *      log wrapping
		 *
		 * option 1 - panic ? No.!
		 * option 2 - shutdown file systems
		 *            associated with log ?
		 * option 3 - extend log ?
		 */
		/*
		 * option 4 - second chance
		 *
		 * mark log wrapped, and continue.
		 * when all active transactions are completed,
		 * mark log vaild for recovery.
		 * if crashed during invalid state, log state
		 * implies invald log, forcing fsck().
		 */
		/* mark log state log wrap in log superblock */
		/* log->state = LOGWRAP; */

		/* reset sync point computation */
		log->syncpt = log->sync = lsn;
		log->nextsync = delta;
	} else
		/* next syncpt trigger = written + more */
		log->nextsync = written + more;

	/* return if lmLogSync() from outside of transaction, e.g., sync() */
	if (nosyncwait)
		return lsn;

	/* if number of bytes written from last sync point is more
	 * than 1/4 of the log size, stop new transactions from
	 * starting until all current transactions are completed
	 * by setting syncbarrier flag.
	 */
	if (written > LOGSYNC_BARRIER(logsize) && logsize > 32 * LOGPSIZE) {
		log->syncbarrier = 1;
		jFYI(1, ("log barrier on: lsn=0x%x syncpt=0x%x\n", lsn,
			 log->syncpt));
	}

	return lsn;
}


/*
 * NAME:	lmLogOpen()
 *
 * FUNCTION:    open the log on first open;
 *	insert filesystem in the active list of the log.
 *
 * PARAMETER:	ipmnt	- file system mount inode
 *		iplog 	- log inode (out)
 *
 * RETURN:
 *
 * serialization:
 */
int lmLogOpen(struct super_block *sb, log_t ** logptr)
{
	int rc;
	struct block_device *bdev;
	log_t *log;

	if (!(log = kmalloc(sizeof(log_t), GFP_KERNEL)))
		return ENOMEM;
	memset(log, 0, sizeof(log_t));

	log->sb = sb;		/* This should be a list */

	if (!(JFS_SBI(sb)->mntflag & JFS_INLINELOG))
		goto externalLog;

	/*
	 *      in-line log in host file system
	 *
	 * file system to log have 1-to-1 relationship;
	 */

	log->flag = JFS_INLINELOG;
	log->bdev = sb->s_bdev;
	log->base = addressPXD(&JFS_SBI(sb)->logpxd);
	log->size = lengthPXD(&JFS_SBI(sb)->logpxd) >>
	    (L2LOGPSIZE - sb->s_blocksize_bits);
	log->l2bsize = sb->s_blocksize_bits;
	ASSERT(L2LOGPSIZE >= sb->s_blocksize_bits);

	/*
	 * initialize log.
	 */
	if ((rc = lmLogInit(log)))
		goto errout10;
	goto out;

	/*
	 *      external log as separate logical volume
	 *
	 * file systems to log may have n-to-1 relationship;
	 */
      externalLog:

	/*
	 * TODO: Check for already opened log devices
	 */

	if (!(bdev = bdget(kdev_t_to_nr(JFS_SBI(sb)->logdev)))) {
		rc = ENODEV;
		goto errout10;
	}

	if ((rc = blkdev_get(bdev, FMODE_READ|FMODE_WRITE, 0, BDEV_FS))) {
		rc = -rc;
		goto errout10;
	}

	log->bdev = bdev;
	memcpy(log->uuid, JFS_SBI(sb)->loguuid, sizeof(log->uuid));
	
	/*
	 * initialize log:
	 */
	if ((rc = lmLogInit(log)))
		goto errout20;

	/*
	 * add file system to log active file system list
	 */
	if ((rc = lmLogFileSystem(log, JFS_SBI(sb)->uuid, 1)))
		goto errout30;

      out:
	jFYI(1, ("lmLogOpen: exit(0)\n"));
	*logptr = log;
	return 0;

	/*
	 *      unwind on error
	 */
      errout30:		/* unwind lbmLogInit() */
	lbmLogShutdown(log);

      errout20:		/* close external log device */
	blkdev_put(bdev, BDEV_FS);

      errout10:		/* free log descriptor */
	kfree(log);

	jFYI(1, ("lmLogOpen: exit(%d)\n", rc));
	return rc;
}


/*
 * NAME:	lmLogInit()
 *
 * FUNCTION:	log initialization at first log open.
 *
 *	logredo() (or logformat()) should have been run previously.
 *	initialize the log inode from log superblock.
 *	set the log state in the superblock to LOGMOUNT and
 *	write SYNCPT log record.
 *		
 * PARAMETER:	log	- log structure
 *
 * RETURN:	0	- if ok
 *		EINVAL	- bad log magic number or superblock dirty
 *		error returned from logwait()
 *			
 * serialization: single first open thread
 */
static int lmLogInit(log_t * log)
{
	int rc = 0;
	lrd_t lrd;
	logsuper_t *logsuper;
	lbuf_t *bpsuper;
	lbuf_t *bp;
	logpage_t *lp;
	int lsn;

	jFYI(1, ("lmLogInit: log:0x%p\n", log));

	/*
	 * log inode is overlaid on generic inode where
	 * dinode have been zeroed out by iRead();
	 */

	/*
	 * initialize log i/o
	 */
	if ((rc = lbmLogInit(log)))
		return rc;

	/*
	 * validate log superblock
	 */


	if (!(log->flag & JFS_INLINELOG))
		log->l2bsize = 12;	/* XXX kludge alert XXX */
	if ((rc = lbmRead(log, 1, &bpsuper)))
		goto errout10;

	logsuper = (logsuper_t *) bpsuper->l_ldata;

	if (logsuper->magic != cpu_to_le32(LOGMAGIC)) {
		jERROR(1, ("*** Log Format Error ! ***\n"));
		rc = EINVAL;
		goto errout20;
	}

	/* logredo() should have been run successfully. */
	if (logsuper->state != cpu_to_le32(LOGREDONE)) {
		jERROR(1, ("*** Log Is Dirty ! ***\n"));
		rc = EINVAL;
		goto errout20;
	}

	/* initialize log inode from log superblock */
	if (log->flag & JFS_INLINELOG) {
		if (log->size != le32_to_cpu(logsuper->size)) {
			rc = EINVAL;
			goto errout20;
		}
		jFYI(0,
		     ("lmLogInit: inline log:0x%p base:0x%Lx size:0x%x\n",
		      log, (unsigned long long) log->base, log->size));
	} else {
		if (memcmp(logsuper->uuid, log->uuid, 16)) {
			jERROR(1,("wrong uuid on JFS log device\n"));
			goto errout20;
		}
		log->size = le32_to_cpu(logsuper->size);
		log->l2bsize = le32_to_cpu(logsuper->l2bsize);
		jFYI(0,
		     ("lmLogInit: external log:0x%p base:0x%Lx size:0x%x\n",
		      log, (unsigned long long) log->base, log->size));
	}

	log->flag |= JFS_GROUPCOMMIT;
/*
	log->flag |= JFS_LAZYCOMMIT;
*/
	log->page = le32_to_cpu(logsuper->end) / LOGPSIZE;
	log->eor = le32_to_cpu(logsuper->end) - (LOGPSIZE * log->page);

	/*
	 * initialize for log append write mode
	 */
	/* establish current/end-of-log page/buffer */
	if ((rc = lbmRead(log, log->page, &bp)))
		goto errout20;

	lp = (logpage_t *) bp->l_ldata;

	jFYI(1, ("lmLogInit: lsn:0x%x page:%d eor:%d:%d\n",
		 le32_to_cpu(logsuper->end), log->page, log->eor,
		 le16_to_cpu(lp->h.eor)));

//      ASSERT(log->eor == lp->h.eor);

	log->bp = bp;
	bp->l_pn = log->page;
	bp->l_eor = log->eor;

	/* initialize the group commit serialization lock */
	LOGGC_LOCK_INIT(log);

	/* if current page is full, move on to next page */
	if (log->eor >= LOGPSIZE - LOGPTLRSIZE)
		lmNextPage(log);

	/* allocate/initialize the log write serialization lock */
	LOG_LOCK_INIT(log);

	/*
	 * initialize log syncpoint
	 */
	/*
	 * write the first SYNCPT record with syncpoint = 0
	 * (i.e., log redo up to HERE !);
	 * remove current page from lbm write queue at end of pageout
	 * (to write log superblock update), but do not release to freelist;
	 */
	lrd.logtid = 0;
	lrd.backchain = 0;
	lrd.type = cpu_to_le16(LOG_SYNCPT);
	lrd.length = 0;
	lrd.log.syncpt.sync = 0;
	lsn = lmWriteRecord(log, NULL, &lrd, NULL);
	bp = log->bp;
	bp->l_ceor = bp->l_eor;
	lp = (logpage_t *) bp->l_ldata;
	lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_eor);
	lbmWrite(log, bp, lbmWRITE | lbmSYNC, 0);
	if ((rc = lbmIOWait(bp, 0)))
		goto errout30;

	/* initialize logsync parameters */
	log->logsize = (log->size - 2) << L2LOGPSIZE;
	log->lsn = lsn;
	log->syncpt = lsn;
	log->sync = log->syncpt;
	log->nextsync = LOGSYNC_DELTA(log->logsize);
	init_waitqueue_head(&log->syncwait);

	jFYI(1, ("lmLogInit: lsn:0x%x syncpt:0x%x sync:0x%x\n",
		 log->lsn, log->syncpt, log->sync));

	LOGSYNC_LOCK_INIT(log);

	INIT_LIST_HEAD(&log->synclist);

	log->cqueue.head = log->cqueue.tail = 0;

	log->count = 0;

	/*
	 * initialize for lazy/group commit
	 */
	log->clsn = lsn;

	/*
	 * update/write superblock
	 */
	logsuper->state = cpu_to_le32(LOGMOUNT);
	log->serial = le32_to_cpu(logsuper->serial) + 1;
	logsuper->serial = cpu_to_le32(log->serial);
	lbmDirectWrite(log, bpsuper, lbmWRITE | lbmRELEASE | lbmSYNC);
	if ((rc = lbmIOWait(bpsuper, lbmFREE)))
		goto errout30;

	jFYI(1, ("lmLogInit: exit(%d)\n", rc));
	return 0;

	/*
	 *      unwind on error
	 */
      errout30:		/* release log page */
	lbmFree(bp);

      errout20:		/* release log superblock */
	lbmFree(bpsuper);

      errout10:		/* unwind lbmLogInit() */
	lbmLogShutdown(log);

	jFYI(1, ("lmLogInit: exit(%d)\n", rc));
	return rc;
}


/*
 * NAME:	lmLogClose()
 *
 * FUNCTION:	remove file system <ipmnt> from active list of log <iplog>
 *		and close it on last close.
 *
 * PARAMETER:	sb	- superblock
 *		log	- log inode
 *
 * RETURN:	errors from subroutines
 *
 * serialization:
 */
int lmLogClose(struct super_block *sb, log_t * log)
{
	int rc;

	jFYI(1, ("lmLogClose: log:0x%p\n", log));

	if (!(log->flag & JFS_INLINELOG))
		goto externalLog;
	
	/*
	 *      in-line log in host file system
	 */
	rc = lmLogShutdown(log);
	goto out;

	/*
	 *      external log as separate logical volume
	 */
      externalLog:
	lmLogFileSystem(log, JFS_SBI(sb)->uuid, 0);
	rc = lmLogShutdown(log);
	blkdev_put(log->bdev, BDEV_FS);

      out:
	jFYI(0, ("lmLogClose: exit(%d)\n", rc));
	return rc;
}


/*
 * NAME:	lmLogShutdown()
 *
 * FUNCTION:	log shutdown at last LogClose().
 *
 *		write log syncpt record.
 *		update super block to set redone flag to 0.
 *
 * PARAMETER:	log	- log inode
 *
 * RETURN:	0	- success
 *			
 * serialization: single last close thread
 */
static int lmLogShutdown(log_t * log)
{
	int rc;
	lrd_t lrd;
	int lsn;
	logsuper_t *logsuper;
	lbuf_t *bpsuper;
	lbuf_t *bp;
	logpage_t *lp;

	jFYI(1, ("lmLogShutdown: log:0x%p\n", log));

	if (log->cqueue.head || !list_empty(&log->synclist)) {
		/*
		 * If there was very recent activity, we may need to wait
		 * for the lazycommit thread to catch up
		 */
		int i;

		for (i = 0; i < 800; i++) {	/* Too much? */
			current->state = TASK_INTERRUPTIBLE;
			schedule_timeout(HZ / 4);
			if ((log->cqueue.head == NULL) &&
			    list_empty(&log->synclist))
				break;
		}
	}
	assert(log->cqueue.head == NULL);
	assert(list_empty(&log->synclist));

	/*
	 * We need to make sure all of the "written" metapages
	 * actually make it to disk
	 */
	fsync_no_super(log->sb->s_dev);

	/*
	 * write the last SYNCPT record with syncpoint = 0
	 * (i.e., log redo up to HERE !)
	 */
	lrd.logtid = 0;
	lrd.backchain = 0;
	lrd.type = cpu_to_le16(LOG_SYNCPT);
	lrd.length = 0;
	lrd.log.syncpt.sync = 0;
	lsn = lmWriteRecord(log, NULL, &lrd, NULL);
	bp = log->bp;
	lp = (logpage_t *) bp->l_ldata;
	lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_eor);
	lbmWrite(log, log->bp, lbmWRITE | lbmRELEASE | lbmSYNC, 0);
	lbmIOWait(log->bp, lbmFREE);

	/*
	 * synchronous update log superblock
	 * mark log state as shutdown cleanly
	 * (i.e., Log does not need to be replayed).
	 */
	if ((rc = lbmRead(log, 1, &bpsuper)))
		goto out;

	logsuper = (logsuper_t *) bpsuper->l_ldata;
	logsuper->state = cpu_to_le32(LOGREDONE);
	logsuper->end = cpu_to_le32(lsn);
	lbmDirectWrite(log, bpsuper, lbmWRITE | lbmRELEASE | lbmSYNC);
	rc = lbmIOWait(bpsuper, lbmFREE);

	jFYI(1, ("lmLogShutdown: lsn:0x%x page:%d eor:%d\n",
		 lsn, log->page, log->eor));

      out:    
	/*
	 * shutdown per log i/o
	 */
	lbmLogShutdown(log);

	if (rc) {
		jFYI(1, ("lmLogShutdown: exit(%d)\n", rc));
	}
	return rc;
}


/*
 * NAME:	lmLogFileSystem()
 *
 * FUNCTION:	insert (<activate> = true)/remove (<activate> = false)
 *	file system into/from log active file system list.
 *
 * PARAMETE:	log	- pointer to logs inode.
 *		fsdev	- kdev_t of filesystem.
 *		serial  - pointer to returned log serial number
 *		activate - insert/remove device from active list.
 *
 * RETURN:	0	- success
 *		errors returned by vms_iowait().
 *			
 * serialization: IWRITE_LOCK(log inode) held on entry/exit
 */
static int lmLogFileSystem(log_t * log, char *uuid, int activate)
{
	int rc = 0;
	int i;
	logsuper_t *logsuper;
	lbuf_t *bpsuper;

	/*
	 * insert/remove file system device to log active file system list.
	 */
	if ((rc = lbmRead(log, 1, &bpsuper)))
		return rc;

	logsuper = (logsuper_t *) bpsuper->l_ldata;
	if (activate) {
		for (i = 0; i < MAX_ACTIVE; i++)
			if (!memcmp(logsuper->active[i].uuid, NULL_UUID, 16)) {
				memcpy(logsuper->active[i].uuid, uuid, 16);
				break;
			}
		if (i == MAX_ACTIVE) {
			jERROR(1,("Too many file systems sharing journal!\n"));
			lbmFree(bpsuper);
			return EMFILE;	/* Is there a better rc? */
		}
	} else {
		for (i = 0; i < MAX_ACTIVE; i++)
			if (!memcmp(logsuper->active[i].uuid, uuid, 16)) {
				memcpy(logsuper->active[i].uuid, NULL_UUID, 16);
				break;
			}
		assert(i < MAX_ACTIVE);
	}

	/*
	 * synchronous write log superblock:
	 *
	 * write sidestream bypassing write queue:
	 * at file system mount, log super block is updated for
	 * activation of the file system before any log record
	 * (MOUNT record) of the file system, and at file system
	 * unmount, all meta data for the file system has been
	 * flushed before log super block is updated for deactivation
	 * of the file system.
	 */
	lbmDirectWrite(log, bpsuper, lbmWRITE | lbmRELEASE | lbmSYNC);
	rc = lbmIOWait(bpsuper, lbmFREE);

	return rc;
}


/*
 *	lmLogQuiesce()
 */
int lmLogQuiesce(log_t * log)
{
	int rc;

	rc = lmLogShutdown(log);

	return rc;
}


/*
 *	lmLogResume()
 */
int lmLogResume(log_t * log, struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	int rc;

	log->base = addressPXD(&sbi->logpxd);
	log->size =
	    (lengthPXD(&sbi->logpxd) << sb->s_blocksize_bits) >> L2LOGPSIZE;
	rc = lmLogInit(log);

	return rc;
}


/*
 *		log buffer manager (lbm)
 *		------------------------
 *
 * special purpose buffer manager supporting log i/o requirements.
 *
 * per log write queue:
 * log pageout occurs in serial order by fifo write queue and
 * restricting to a single i/o in pregress at any one time.
 * a circular singly-linked list
 * (log->wrqueue points to the tail, and buffers are linked via
 * bp->wrqueue field), and
 * maintains log page in pageout ot waiting for pageout in serial pageout.
 */

/*
 *	lbmLogInit()
 *
 * initialize per log I/O setup at lmLogInit()
 */
static int lbmLogInit(log_t * log)
{				/* log inode */
	int i;
	lbuf_t *lbuf;

	jFYI(1, ("lbmLogInit: log:0x%p\n", log));

	/* initialize current buffer cursor */
	log->bp = NULL;

	/* initialize log device write queue */
	log->wqueue = NULL;

	/*
	 * Each log has its own buffer pages allocated to it.  These are
	 * not managed by the page cache.  This ensures that a transaction
	 * writing to the log does not block trying to allocate a page from
	 * the page cache (for the log).  This would be bad, since page
	 * allocation waits on the kswapd thread that may be committing inodes
	 * which would cause log activity.  Was that clear?  I'm trying to
	 * avoid deadlock here.
	 */
	init_waitqueue_head(&log->free_wait);

	log->lbuf_free = NULL;

	for (i = 0; i < LOGPAGES; i++) {
		lbuf = kmalloc(sizeof(lbuf_t), GFP_KERNEL);
		if (lbuf == 0)
			goto error;
		lbuf->l_bh.b_data = lbuf->l_ldata =
		    (char *) __get_free_page(GFP_KERNEL);
		if (lbuf->l_ldata == 0) {
			kfree(lbuf);
			goto error;
		}
		lbuf->l_log = log;
		init_waitqueue_head(&lbuf->l_ioevent);

		lbuf->l_bh.b_size = LOGPSIZE;
		lbuf->l_bh.b_dev = to_kdev_t(log->bdev->bd_dev);
		lbuf->l_bh.b_end_io = lbmIODone;
		lbuf->l_bh.b_private = lbuf;
		lbuf->l_bh.b_page = virt_to_page(lbuf->l_ldata);
		lbuf->l_bh.b_state = 0;
		init_waitqueue_head(&lbuf->l_bh.b_wait);

		lbuf->l_freelist = log->lbuf_free;
		log->lbuf_free = lbuf;
	}

	return (0);

      error:
	lbmLogShutdown(log);
	return (ENOMEM);
}


/*
 *	lbmLogShutdown()
 *
 * finalize per log I/O setup at lmLogShutdown()
 */
static void lbmLogShutdown(log_t * log)
{
	lbuf_t *lbuf;

	jFYI(1, ("lbmLogShutdown: log:0x%p\n", log));

	lbuf = log->lbuf_free;
	while (lbuf) {
		lbuf_t *next = lbuf->l_freelist;
		free_page((unsigned long) lbuf->l_ldata);
		kfree(lbuf);
		lbuf = next;
	}

	log->bp = NULL;
}


/*
 *	lbmAllocate()
 *
 * allocate an empty log buffer
 */
static lbuf_t *lbmAllocate(log_t * log, int pn)
{
	lbuf_t *bp;
	unsigned long flags;

	/*
	 * recycle from log buffer freelist if any
	 */
	LCACHE_LOCK(flags);
	LCACHE_SLEEP_COND(log->free_wait, (bp = log->lbuf_free), flags);
	log->lbuf_free = bp->l_freelist;
	LCACHE_UNLOCK(flags);

	bp->l_flag = 0;

	bp->l_wqnext = NULL;
	bp->l_freelist = NULL;

	bp->l_pn = pn;
	bp->l_blkno = log->base + (pn << (L2LOGPSIZE - log->l2bsize));
	bp->l_bh.b_blocknr = bp->l_blkno;
	bp->l_ceor = 0;

	return bp;
}


/*
 *	lbmFree()
 *
 * release a log buffer to freelist
 */
static void lbmFree(lbuf_t * bp)
{
	unsigned long flags;

	LCACHE_LOCK(flags);

	lbmfree(bp);

	LCACHE_UNLOCK(flags);
}

static void lbmfree(lbuf_t * bp)
{
	log_t *log = bp->l_log;

	assert(bp->l_wqnext == NULL);

	/*
	 * return the buffer to head of freelist
	 */
	bp->l_freelist = log->lbuf_free;
	log->lbuf_free = bp;

	wake_up(&log->free_wait);
	return;
}


/*
 * NAME:	lbmRedrive
 *
 * FUNCTION:	add a log buffer to the the log redrive list
 *
 * PARAMETER:
 *     bp	- log buffer
 *
 * NOTES:
 *	Takes log_redrive_lock.
 */
static inline void lbmRedrive(lbuf_t *bp)
{
	unsigned long flags;

	spin_lock_irqsave(&log_redrive_lock, flags);
	bp->l_redrive_next = log_redrive_list;
	log_redrive_list = bp;
	spin_unlock_irqrestore(&log_redrive_lock, flags);

	wake_up(&jfs_IO_thread_wait);
}


/*
 *	lbmRead()
 */
static int lbmRead(log_t * log, int pn, lbuf_t ** bpp)
{
	lbuf_t *bp;

	/*
	 * allocate a log buffer
	 */
	*bpp = bp = lbmAllocate(log, pn);
	jFYI(1, ("lbmRead: bp:0x%p pn:0x%x\n", bp, pn));

	bp->l_flag |= lbmREAD;
	bp->l_bh.b_reqnext = NULL;
	clear_bit(BH_Uptodate, &bp->l_bh.b_state);
	lock_buffer(&bp->l_bh);
	set_bit(BH_Mapped, &bp->l_bh.b_state);
	set_bit(BH_Req, &bp->l_bh.b_state);
	bp->l_bh.b_rdev = bp->l_bh.b_dev;
	bp->l_bh.b_rsector = bp->l_blkno << (log->l2bsize - 9);
	generic_make_request(READ, &bp->l_bh);
	run_task_queue(&tq_disk);

	wait_event(bp->l_ioevent, (bp->l_flag != lbmREAD));

	return 0;
}


/*
 *	lbmWrite()
 *
 * buffer at head of pageout queue stays after completion of
 * partial-page pageout and redriven by explicit initiation of
 * pageout by caller until full-page pageout is completed and
 * released.
 *
 * device driver i/o done redrives pageout of new buffer at
 * head of pageout queue when current buffer at head of pageout
 * queue is released at the completion of its full-page pageout.
 *
 * LOGGC_LOCK() serializes lbmWrite() by lmNextPage() and lmGroupCommit().
 * LCACHE_LOCK() serializes xflag between lbmWrite() and lbmIODone()
 */
static void lbmWrite(log_t * log, lbuf_t * bp, int flag, int cant_block)
{
	lbuf_t *tail;
	unsigned long flags;

	jFYI(1, ("lbmWrite: bp:0x%p flag:0x%x pn:0x%x\n",
		 bp, flag, bp->l_pn));

	/* map the logical block address to physical block address */
	bp->l_blkno =
	    log->base + (bp->l_pn << (L2LOGPSIZE - log->l2bsize));

	LCACHE_LOCK(flags);		/* disable+lock */

	/*
	 * initialize buffer for device driver
	 */
	bp->l_flag = flag;

	/*
	 *      insert bp at tail of write queue associated with log
	 *
	 * (request is either for bp already/currently at head of queue
	 * or new bp to be inserted at tail)
	 */
	tail = log->wqueue;

	/* is buffer not already on write queue ? */
	if (bp->l_wqnext == NULL) {
		/* insert at tail of wqueue */
		if (tail == NULL) {
			log->wqueue = bp;
			bp->l_wqnext = bp;
		} else {
			log->wqueue = bp;
			bp->l_wqnext = tail->l_wqnext;
			tail->l_wqnext = bp;
		}

		tail = bp;
	}

	/* is buffer at head of wqueue and for write ? */
	if ((bp != tail->l_wqnext) || !(flag & lbmWRITE)) {
		LCACHE_UNLOCK(flags);	/* unlock+enable */
		return;
	}

	LCACHE_UNLOCK(flags);	/* unlock+enable */

	if (cant_block)
		lbmRedrive(bp);
	else if (flag & lbmSYNC)
		lbmStartIO(bp);
	else {
		LOGGC_UNLOCK(log);
		lbmStartIO(bp);
		LOGGC_LOCK(log);
	}
}


/*
 *	lbmDirectWrite()
 *
 * initiate pageout bypassing write queue for sidestream
 * (e.g., log superblock) write;
 */
static void lbmDirectWrite(log_t * log, lbuf_t * bp, int flag)
{
	jEVENT(0, ("lbmDirectWrite: bp:0x%p flag:0x%x pn:0x%x\n",
		   bp, flag, bp->l_pn));

	/*
	 * initialize buffer for device driver
	 */
	bp->l_flag = flag | lbmDIRECT;

	/* map the logical block address to physical block address */
	bp->l_blkno =
	    log->base + (bp->l_pn << (L2LOGPSIZE - log->l2bsize));

	/*
	 *      initiate pageout of the page
	 */
	lbmStartIO(bp);
}


/*
 * NAME:	lbmStartIO()
 *
 * FUNCTION:	Interface to DD strategy routine
 *
 * RETURN:      none
 *
 * serialization: LCACHE_LOCK() is NOT held during log i/o;
 */
void lbmStartIO(lbuf_t * bp)
{
	jFYI(1, ("lbmStartIO\n"));

	bp->l_bh.b_reqnext = NULL;
	set_bit(BH_Dirty, &bp->l_bh.b_state);
//      lock_buffer(&bp->l_bh);
	assert(!test_bit(BH_Lock, &bp->l_bh.b_state));
	set_bit(BH_Lock, &bp->l_bh.b_state);

	set_bit(BH_Mapped, &bp->l_bh.b_state);
	set_bit(BH_Req, &bp->l_bh.b_state);
	bp->l_bh.b_rdev = bp->l_bh.b_dev;
	bp->l_bh.b_rsector = bp->l_blkno << (bp->l_log->l2bsize - 9);
	generic_make_request(WRITE, &bp->l_bh);

	INCREMENT(lmStat.submitted);
	run_task_queue(&tq_disk);

	jFYI(1, ("lbmStartIO done\n"));
}


/*
 *	lbmIOWait()
 */
static int lbmIOWait(lbuf_t * bp, int flag)
{
	unsigned long flags;
	int rc = 0;

	jFYI(1,
	     ("lbmIOWait1: bp:0x%p flag:0x%x:0x%x\n", bp, bp->l_flag,
	      flag));

	LCACHE_LOCK(flags);		/* disable+lock */

	LCACHE_SLEEP_COND(bp->l_ioevent, (bp->l_flag & lbmDONE), flags);

	rc = (bp->l_flag & lbmERROR) ? EIO : 0;

	if (flag & lbmFREE)
		lbmfree(bp);

	LCACHE_UNLOCK(flags);	/* unlock+enable */

	jFYI(1,
	     ("lbmIOWait2: bp:0x%p flag:0x%x:0x%x\n", bp, bp->l_flag,
	      flag));
	return rc;
}

/*
 *	lbmIODone()
 *
 * executed at INTIODONE level
 */
static void lbmIODone(struct buffer_head *bh, int uptodate)
{
	lbuf_t *bp = bh->b_private;
	lbuf_t *nextbp, *tail;
	log_t *log;
	unsigned long flags;

	/*
	 * get back jfs buffer bound to the i/o buffer
	 */
	jEVENT(0, ("lbmIODone: bp:0x%p flag:0x%x\n", bp, bp->l_flag));

	LCACHE_LOCK(flags);		/* disable+lock */

	unlock_buffer(&bp->l_bh);
	bp->l_flag |= lbmDONE;

	if (!uptodate) {
		bp->l_flag |= lbmERROR;

		jERROR(1, ("lbmIODone: I/O error in JFS log\n"));
	}

	/*
	 *      pagein completion
	 */
	if (bp->l_flag & lbmREAD) {
		bp->l_flag &= ~lbmREAD;

		LCACHE_UNLOCK(flags);	/* unlock+enable */

		/* wakeup I/O initiator */
		LCACHE_WAKEUP(&bp->l_ioevent);

		return;
	}

	/*
	 *      pageout completion
	 *
	 * the bp at the head of write queue has completed pageout.
	 *
	 * if single-commit/full-page pageout, remove the current buffer
	 * from head of pageout queue, and redrive pageout with
	 * the new buffer at head of pageout queue;
	 * otherwise, the partial-page pageout buffer stays at
	 * the head of pageout queue to be redriven for pageout
	 * by lmGroupCommit() until full-page pageout is completed.
	 */
	bp->l_flag &= ~lbmWRITE;
	INCREMENT(lmStat.pagedone);

	/* update committed lsn */
	log = bp->l_log;
	log->clsn = (bp->l_pn << L2LOGPSIZE) + bp->l_ceor;

	if (bp->l_flag & lbmDIRECT) {
		LCACHE_WAKEUP(&bp->l_ioevent);
		LCACHE_UNLOCK(flags);
		return;
	}

	tail = log->wqueue;

	/* single element queue */
	if (bp == tail) {
		/* remove head buffer of full-page pageout
		 * from log device write queue
		 */
		if (bp->l_flag & lbmRELEASE) {
			log->wqueue = NULL;
			bp->l_wqnext = NULL;
		}
	}
	/* multi element queue */
	else {
		/* remove head buffer of full-page pageout
		 * from log device write queue
		 */
		if (bp->l_flag & lbmRELEASE) {
			nextbp = tail->l_wqnext = bp->l_wqnext;
			bp->l_wqnext = NULL;

			/*
			 * redrive pageout of next page at head of write queue:
			 * redrive next page without any bound tblk
			 * (i.e., page w/o any COMMIT records), or
			 * first page of new group commit which has been
			 * queued after current page (subsequent pageout
			 * is performed synchronously, except page without
			 * any COMMITs) by lmGroupCommit() as indicated
			 * by lbmWRITE flag;
			 */
			if (nextbp->l_flag & lbmWRITE) {
				/*
				 * We can't do the I/O at interrupt time.
				 * The jfsIO thread can do it
				 */
				lbmRedrive(nextbp);
			}
		}
	}

	/*
	 *      synchronous pageout:
	 *
	 * buffer has not necessarily been removed from write queue
	 * (e.g., synchronous write of partial-page with COMMIT):
	 * leave buffer for i/o initiator to dispose
	 */
	if (bp->l_flag & lbmSYNC) {
		LCACHE_UNLOCK(flags);	/* unlock+enable */

		/* wakeup I/O initiator */
		LCACHE_WAKEUP(&bp->l_ioevent);
	}

	/*
	 *      Group Commit pageout:
	 */
	else if (bp->l_flag & lbmGC) {
		LCACHE_UNLOCK(flags);
		lmPostGC(bp);
	}

	/*
	 *      asynchronous pageout:
	 *
	 * buffer must have been removed from write queue:
	 * insert buffer at head of freelist where it can be recycled
	 */
	else {
		assert(bp->l_flag & lbmRELEASE);
		assert(bp->l_flag & lbmFREE);
		lbmfree(bp);

		LCACHE_UNLOCK(flags);	/* unlock+enable */
	}
}

int jfsIOWait(void *arg)
{
	lbuf_t *bp;

	jFYI(1, ("jfsIOWait is here!\n"));

	lock_kernel();

	daemonize();
	current->tty = NULL;
	strcpy(current->comm, "jfsIO");

	unlock_kernel();

	spin_lock_irq(&current->sigmask_lock);
	sigfillset(&current->blocked);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);

	complete(&jfsIOwait);

	do {
		DECLARE_WAITQUEUE(wq, current);

		spin_lock_irq(&log_redrive_lock);
		while ((bp = log_redrive_list)) {
			log_redrive_list = bp->l_redrive_next;
			bp->l_redrive_next = NULL;
			spin_unlock_irq(&log_redrive_lock);
			lbmStartIO(bp);
			spin_lock_irq(&log_redrive_lock);
		}
		add_wait_queue(&jfs_IO_thread_wait, &wq);
		set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock_irq(&log_redrive_lock);
		schedule();
		current->state = TASK_RUNNING;
		remove_wait_queue(&jfs_IO_thread_wait, &wq);
	} while (!jfs_stop_threads);

	jFYI(1,("jfsIOWait being killed!\n"));
	complete(&jfsIOwait);
	return 0;
}



/*
 * NAME:	lmLogFormat()/jfs_logform()
 *
 * FUNCTION:	format file system log (ref. jfs_logform()).
 *
 * PARAMETERS:
 *      sb      - superblock
 *	logAddress - start address of log space in FS block
 *	logSize	- length of log space in FS block;
 *
 * RETURN:	 0 -	success
 *		-1 -	i/o error
 */
int lmLogFormat(struct super_block *sb, s64 logAddress, int logSize)
{
	int rc = 0;
	logsuper_t *logsuper;
	logpage_t *lp;
	int lspn;		/* log sequence page number */
	struct lrd *lrd_ptr;
	int npages = 0;
	metapage_t *bp;

	jFYI(0, ("lmLogFormat: logAddress:%Ld logSize:%d\n",
		 (long long)logAddress, logSize));

	/* allocate a JFS buffer */
	bp = (metapage_t *) __get_free_pages(GFP_KERNEL,0);

	/* map the logical block address to physical block address */
	/*bp->cm_blkno = logAddress << JFS_SBI(sb)->s_l2bfactor;*/
	
        /*npbperpage = LOGPSIZE >> JFS_SBI(sb)->s_l2pbsize;*/
	npages = logSize / (LOGPSIZE >> JFS_SBI(sb)->l2bsize);

	/*
	 *      log space:
	 *
	 * page 0 - reserved;
	 * page 1 - log superblock;
	 * page 2 - log data page: A SYNC log record is written
	 *          into this page at logform time;
	 * pages 3-N - log data page: set to empty log data pages;
	 */
	/*
	 *      init log superblock: log page 1
	 */
	logsuper = (logsuper_t *) bp->data;
	logsuper->magic = cpu_to_le32(LOGMAGIC);
	logsuper->version = cpu_to_le32(LOGVERSION);
	logsuper->state = cpu_to_le32(LOGREDONE);
	logsuper->flag = cpu_to_le32(JFS_SBI(sb)->mntflag);	/* ? */
	logsuper->size = cpu_to_le32(npages);
	logsuper->bsize = cpu_to_le32(JFS_SBI(sb)->bsize);
	logsuper->l2bsize = cpu_to_le32(JFS_SBI(sb)->l2bsize);
	logsuper->end = cpu_to_le32(2 * LOGPSIZE + LOGPHDRSIZE + LOGRDSIZE);

	/*bp->cm_blkno += npbperpage;*/
	flush_metapage(bp);

	/*
	 *      init pages 2 to npages-1 as log data pages:
	 *
	 * log page sequence number (lpsn) initialization:
	 *
	 * pn:   0     1     2     3                 n-1
	 *       +-----+-----+=====+=====+===.....===+=====+
	 * lspn:             N-1   0     1           N-2
	 *                   <--- N page circular file ---->
	 *
	 * the N (= npages-2) data pages of the log is maintained as
	 * a circular file for the log records;
	 * lpsn grows by 1 monotonically as each log page is written
	 * to the circular file of the log;
	 * and setLogpage() will not reset the page number even if
	 * the eor is equal to LOGPHDRSIZE. In order for binary search
	 * still work in find log end process, we have to simulate the
	 * log wrap situation at the log format time.
	 * The 1st log page written will have the highest lpsn. Then
	 * the succeeding log pages will have ascending order of
	 * the lspn starting from 0, ... (N-2)
	 */
	lp = (logpage_t *) bp->data;
	/*
	 * initialize 1st log page to be written: lpsn = N - 1,
	 * write a SYNCPT log record is written to this page
	 */
	lp->h.page = lp->t.page = cpu_to_le32(npages - 3);
	lp->h.eor = lp->t.eor = cpu_to_le16(LOGPHDRSIZE + LOGRDSIZE);

	lrd_ptr = (struct lrd *) &lp->data;
	lrd_ptr->logtid = 0;
	lrd_ptr->backchain = 0;
	lrd_ptr->type = cpu_to_le16(LOG_SYNCPT);
	lrd_ptr->length = 0;
	lrd_ptr->log.syncpt.sync = 0;

	/*bp->cm_blkno += npbperpage;*/
	flush_metapage(bp);

	/*
	 *      initialize succeeding log pages: lpsn = 0, 1, ..., (N-2)
	 */
	for (lspn = 0; lspn < npages - 3; lspn++) {
		lp->h.page = lp->t.page = cpu_to_le32(lspn);
		lp->h.eor = lp->t.eor = cpu_to_le16(LOGPHDRSIZE);

		/*bp->cm_blkno += npbperpage;*/
		flush_metapage(bp);
	}

	/*
	 *      finalize log
	 */
	/* release the buffer */
	free_page((unsigned long) bp);

	return rc;
}


#ifdef CONFIG_JFS_STATISTICS
int jfs_lmstats_read(char *buffer, char **start, off_t offset, int length,
		      int *eof, void *data)
{
	int len = 0;
	off_t begin;

	len += sprintf(buffer,
		       "JFS Logmgr stats\n"
		       "================\n"
		       "commits = %d\n"
		       "writes submitted = %d\n"
		       "writes completed = %d\n",
		       lmStat.commit,
		       lmStat.submitted,
		       lmStat.pagedone);

	begin = offset;
	*start = buffer + begin;
	len -= begin;

	if (len > length)
		len = length;
	else
		*eof = 1;

	if (len < 0)
		len = 0;

	return len;
}
#endif /* CONFIG_JFS_STATISTICS */

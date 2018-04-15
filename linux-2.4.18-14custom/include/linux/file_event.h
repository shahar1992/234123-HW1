#ifndef _LINUX_FILE_EVENT_H
#define _LINUX_FLIE_EVENT_H

#define FEVT_OPEN  0x01
#define FEVT_CLOSE 0x02

#define MAX_EVENTS 100 /* The maximum number of events tracked per process */

struct file_event {
	unsigned char type;
	char *filename;
};

struct file_event_monitor {
	bool recording;
	struct file_event* file_events;
	int head_index;
	int tail_index;
};

extern void file_event_monitor_init(struct file_event_monitor *monitor);
//{
//	monitor->recording =  false;
//	monitor->file_events = NULL;
//	monitor->head_index=0;
//	monitor->tail_index=0;
//}

extern void file_event_monitor_enq_event(struct file_event_monitor *monitor,
		char *filename, unsigned char event_type);
//{
//	if (!monitor->recording) return;
//	if (monitor->file_events = NULL)
//		monitor->file_events = kmalloc(....);
//	// need to deq old event if no more room
//      monitor->file_events[monitor->head_index]->type = event_type;
//      monitor->file_events[monitor->head_index]->filename = strdup(filename);
//      monitor->head_index = (monitor->head_index + 1) % MAX_EVENTS;
//}

#endif

#ifndef _MP4MUX_LIST_H
#define _MP4MUX_LIST_H
/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole mp4mux_lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

typedef struct mp4mux_list_head {
	struct mp4mux_list_head *next, *prev;
} mp4mux_list_t;

#define MP4MUX_LIST_HEAD_INIT(name) { &(name), &(name) }

#define MP4MUX_LIST_HEAD(name) \
	mp4mux_list_t name = LIST_HEAD_INIT(name)

#define MP4MUX_INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries. 
 *
 * This is only for internal mp4mux_list manipulation where we know
 * the prev/next entries already!
 */

static inline void  prefetch(void *p){}
 
static inline void __mp4mux_list_add(mp4mux_list_t *_new,
			      mp4mux_list_t *prev,
			      mp4mux_list_t *next)
{
	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	prev->next = _new;
}

/**
 * mp4mux_list_add - add a new entry
 * @new: new entry to be added
 * @head: mp4mux_list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void mp4mux_list_add(mp4mux_list_t *_new, mp4mux_list_t *head)
{
	__mp4mux_list_add(_new, head, head->next);
}

/**
 * mp4mux_list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: mp4mux_list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void mp4mux_list_add_tail(mp4mux_list_t *_new, mp4mux_list_t *head)
{
	__mp4mux_list_add(_new, head->prev, head);
}

/*
 * Delete a mp4mux_list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal mp4mux_list manipulation where we know
 * the prev/next entries already!
 */
static inline void __mp4mux_list_del(mp4mux_list_t *prev, mp4mux_list_t *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * mp4mux_list_del - deletes entry from mp4mux_list.
 * @entry: the element to delete from the mp4mux_list.
 * Note: mp4mux_list_empty on entry does not return true after this, the entry is in an undefined state.
 */
static inline void mp4mux_list_del(mp4mux_list_t *entry)
{
	__mp4mux_list_del(entry->prev, entry->next);
	entry->next = (void *) 0;
	entry->prev = (void *) 0;
}

/**
 * mp4mux_list_del_init - deletes entry from mp4mux_list and reinitialize it.
 * @entry: the element to delete from the mp4mux_list.
 */
static inline void mp4mux_list_del_init(mp4mux_list_t *entry)
{
	__mp4mux_list_del(entry->prev, entry->next);
	MP4MUX_INIT_LIST_HEAD(entry); 
}

/**
 * mp4mux_list_move - delete from one mp4mux_list and add as another's head
 * @mp4mux_list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void mp4mux_list_move(mp4mux_list_t *mp4mux_list, mp4mux_list_t *head)
{
        __mp4mux_list_del(mp4mux_list->prev, mp4mux_list->next);
        mp4mux_list_add(mp4mux_list, head);
}

/**
 * mp4mux_list_move_tail - delete from one mp4mux_list and add as another's tail
 * @mp4mux_list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void mp4mux_list_move_tail(mp4mux_list_t *mp4mux_list,
				  mp4mux_list_t *head)
{
        __mp4mux_list_del(mp4mux_list->prev, mp4mux_list->next);
        mp4mux_list_add_tail(mp4mux_list, head);
}

/**
 * mp4mux_list_empty - tests whether a mp4mux_list is empty
 * @head: the mp4mux_list to test.
 */
static inline int mp4mux_list_empty(mp4mux_list_t *head)
{
	return head->next == head;
}

static inline void __mp4mux_list_splice(mp4mux_list_t *mp4mux_list,
				 mp4mux_list_t *head)
{
	mp4mux_list_t *first = mp4mux_list->next;
	mp4mux_list_t *last = mp4mux_list->prev;
	mp4mux_list_t *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

/**
 * mp4mux_list_splice - join two mp4mux_lists
 * @mp4mux_list: the new mp4mux_list to add.
 * @head: the place to add it in the first mp4mux_list.
 */
static inline void mp4mux_list_splice(mp4mux_list_t *mp4mux_list, mp4mux_list_t *head)
{
	if (!mp4mux_list_empty(mp4mux_list))
		__mp4mux_list_splice(mp4mux_list, head);
}

/**
 * mp4mux_list_splice_init - join two mp4mux_lists and reinitialise the emptied mp4mux_list.
 * @mp4mux_list: the new mp4mux_list to add.
 * @head: the place to add it in the first mp4mux_list.
 *
 * The mp4mux_list at @mp4mux_list is reinitialised
 */
static inline void mp4mux_list_splice_init(mp4mux_list_t *mp4mux_list,
				    mp4mux_list_t *head)
{
	if (!mp4mux_list_empty(mp4mux_list)) {
		__mp4mux_list_splice(mp4mux_list, head);
		MP4MUX_INIT_LIST_HEAD(mp4mux_list);
	}
}

/**
 * mp4mux_list_entry - get the struct for this entry
 * @ptr:	the &mp4mux_list_t pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the mp4mux_list_struct within the struct.
 */
#define mp4mux_list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * mp4mux_list_for_each	-	iterate over a mp4mux_list
 * @pos:	the &mp4mux_list_t to use as a loop counter.
 * @head:	the head for your mp4mux_list.
 */
#define mp4mux_list_for_each(pos, head) \
	for (pos = (head)->next, prefetch(pos->next); pos != (head); \
        	pos = pos->next, prefetch(pos->next))

/**
 * __mp4mux_list_for_each	-	iterate over a mp4mux_list
 * @pos:	the &mp4mux_list_t to use as a loop counter.
 * @head:	the head for your mp4mux_list.
 *
 * This variant differs from mp4mux_list_for_each() in that it's the
 * simplest possible mp4mux_list iteration code, no prefetching is done.
 * Use this for code that knows the mp4mux_list to be very short (empty
 * or 1 entry) most of the time.
 */
#define __mp4mux_list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * mp4mux_list_for_each_prev	-	iterate over a mp4mux_list backwards
 * @pos:	the &mp4mux_list_t to use as a loop counter.
 * @head:	the head for your mp4mux_list.
 */
#define mp4mux_list_for_each_prev(pos, head) \
	for (pos = (head)->prev, prefetch(pos->prev); pos != (head); \
        	pos = pos->prev, prefetch(pos->prev))
        	
/**
 * mp4mux_list_for_each_safe	-	iterate over a mp4mux_list safe against removal of mp4mux_list entry
 * @pos:	the &mp4mux_list_t to use as a loop counter.
 * @n:		another &mp4mux_list_t to use as temporary storage
 * @head:	the head for your mp4mux_list.
 */
#define mp4mux_list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * mp4mux_list_for_each_entry	-	iterate over mp4mux_list of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your mp4mux_list.
 * @member:	the name of the mp4mux_list_struct within the struct.
 */
#define mp4mux_list_for_each_entry(pos, head, member)				\
	for (pos = mp4mux_list_entry((head)->next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head); 					\
	     pos = mp4mux_list_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next))
#endif

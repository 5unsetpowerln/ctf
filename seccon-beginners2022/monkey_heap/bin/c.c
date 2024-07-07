struct rtld_global _rtld_global = {
/* Get architecture specific initializer.  */
#include <dl-procruntime.c>
    /* Generally the default presumption without further information is an
     * executable stack but this is not true for all platforms.  */
    ._dl_stack_flags = DEFAULT_STACK_PERMS,
#ifdef _LIBC_REENTRANT
    ._dl_load_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
    ._dl_load_write_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
    ._dl_load_tls_lock = _RTLD_LOCK_RECURSIVE_INITIALIZER,
#endif
    ._dl_nns = 1,
    ._dl_ns = {
#ifdef _LIBC_REENTRANT
        [LM_ID_BASE] =
            {._ns_unique_sym_table = {.lock = _RTLD_LOCK_RECURSIVE_INITIALIZER}}
#endif
    }};

/* First see whether an array is given.  */
if (l->l_info[DT_FINI_ARRAY] != NULL) {
  ElfW(Addr) *array =
      (ElfW(Addr) *)(l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
  unsigned int i =
      (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof(ElfW(Addr)));
  while (i-- > 0)
    ((fini_t)array[i])();
}

struct rtld_global {
#endif
  /* Don't change the order of the following elements.  'dl_loaded'
     must remain the first element.  Forever.  */

/* Non-shared code has no support for multiple namespaces.  */
#ifdef SHARED
#define DL_NNS 16
#else
#define DL_NNS 1
#endif
  EXTERN struct link_namespaces {
    /* A pointer to the map for the main map.  */
    struct link_map *_ns_loaded;
    /* Number of object in the _dl_loaded list.  */
    unsigned int _ns_nloaded;
    /* Direct pointer to the searchlist of the main object.  */
    struct r_scope_elem *_ns_main_searchlist;
    /* This is zero at program start to signal that the global scope map is
       allocated by rtld.  Later it keeps the size of the map.  It might be
       reset if in _dl_close if the last global object is removed.  */
    size_t _ns_global_scope_alloc;
    /* Search table for unique objects.  */
    struct unique_sym_table {
      __rtld_lock_define_recursive(, lock) struct unique_sym {
        uint32_t hashval;
        const char *name;
        const ElfW(Sym) * sym;
        const struct link_map *map;
      } *entries;
      size_t size;
      size_t n_elements;
      void (*free)(void *);
    } _ns_unique_sym_table;
    /* Keep track of changes to each namespace' list.  */
    struct r_debug _ns_debug;
  } _dl_ns[DL_NNS];
  /* One higher than index of last used namespace.  */
  EXTERN size_t _dl_nns;

  /* During the program run we must not modify the global data of
     loaded shared object simultanously in two threads.  Therefore we
     protect `_dl_open' and `_dl_close' in dl-close.c.

     This must be a recursive lock since the initializer function of
     the loaded object might as well require a call to this function.
     At this time it is not anymore a problem to modify the tables.  */
  __rtld_lock_define_recursive(EXTERN, _dl_load_lock)
      /* This lock is used to keep __dl_iterate_phdr from inspecting the
         list of loaded objects while an object is added to or removed
         from that list.  */
      __rtld_lock_define_recursive(EXTERN, _dl_load_write_lock)

      /* Incremented whenever something may have been added to dl_loaded.  */
      EXTERN unsigned long long _dl_load_adds;

  /* The object to be initialized first.  */
  EXTERN struct link_map *_dl_initfirst;

#if HP_SMALL_TIMING_AVAIL
  /* Start time on CPU clock.  */
  EXTERN hp_timing_t _dl_cpuclock_offset;
#endif

  /* Map of shared object to be profiled.  */
  EXTERN struct link_map *_dl_profile_map;

  /* Counters for the number of relocations performed.  */
  EXTERN unsigned long int _dl_num_relocations;
  EXTERN unsigned long int _dl_num_cache_relocations;

  /* List of search directories.  */
  EXTERN struct r_search_path_elem *_dl_all_dirs;

  /* Structure describing the dynamic linker itself.  We need to
     reserve memory for the data the audit libraries need.  */
  EXTERN struct link_map _dl_rtld_map;
#ifdef SHARED
  struct auditstate audit_data[DL_NNS];
#endif

#if defined SHARED && defined _LIBC_REENTRANT &&                               \
    defined __rtld_lock_default_lock_recursive
  EXTERN void (*_dl_rtld_lock_recursive)(void *);
  EXTERN void (*_dl_rtld_unlock_recursive)(void *);
#endif

  /* Get architecture specific definitions.  */
#define PROCINFO_DECL
#ifndef PROCINFO_CLASS
#define PROCINFO_CLASS EXTERN
#endif
#include <dl-procruntime.c>

  /* If loading a shared object requires that we make the stack executable
     when it was not, we do it by calling this function.
     It returns an errno code or zero on success.  */
  EXTERN int (*_dl_make_stack_executable_hook)(void **);

  /* Prevailing state of the stack, PF_X indicating it's executable.  */
  EXTERN ElfW(Word) _dl_stack_flags;

  /* Flag signalling whether there are gaps in the module ID allocation.  */
  EXTERN bool _dl_tls_dtv_gaps;
  /* Highest dtv index currently needed.  */
  EXTERN size_t _dl_tls_max_dtv_idx;
  /* Information about the dtv slots.  */
  EXTERN struct dtv_slotinfo_list {
    size_t len;
    struct dtv_slotinfo_list *next;
    struct dtv_slotinfo {
      size_t gen;
      struct link_map *map;
    } slotinfo[0];
  } *_dl_tls_dtv_slotinfo_list;
  /* Number of modules in the static TLS block.  */
  EXTERN size_t _dl_tls_static_nelem;
  /* Size of the static TLS block.  */
  EXTERN size_t _dl_tls_static_size;
  /* Size actually allocated in the static TLS block.  */
  EXTERN size_t _dl_tls_static_used;
  /* Alignment requirement of the static TLS block.  */
  EXTERN size_t _dl_tls_static_align;

/* Number of additional entries in the slotinfo array of each slotinfo
   list element.  A large number makes it almost certain take we never
   have to iterate beyond the first element in the slotinfo list.  */
#define TLS_SLOTINFO_SURPLUS (62)

/* Number of additional slots in the dtv allocated.  */
#define DTV_SURPLUS (14)

  /* Initial dtv of the main thread, not allocated with normal malloc.  */
  EXTERN void *_dl_initial_dtv;
  /* Generation counter for the dtv.  */
  EXTERN size_t _dl_tls_generation;

  EXTERN void (*_dl_init_static_tls)(struct link_map *);

  EXTERN void (*_dl_wait_lookup_done)(void);

  /* Scopes to free after next THREAD_GSCOPE_WAIT ().  */
  EXTERN struct dl_scope_free_list {
    size_t count;
    void *list[50];
  } *_dl_scope_free_list;
#if !THREAD_GSCOPE_IN_TCB
  EXTERN int _dl_thread_gscope_count;
#endif
#ifdef SHARED
};

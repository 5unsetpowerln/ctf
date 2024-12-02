void attribute_hidden _IO_vtable_check(void) {
#ifdef SHARED
	/* Honor the compatibility flag.  */
	void (*flag)(void) = atomic_load_relaxed(&IO_accept_foreign_vtables);
	PTR_DEMANGLE(flag);
	if (flag == &_IO_vtable_check)
		return;

	/* In case this libc copy is in a non-default namespace, we always
	   need to accept foreign vtables because there is always a
	   possibility that FILE * objects are passed across the linking
	   boundary.  */
	{
		Dl_info di;
		struct link_map *l;
		if (!rtld_active() || (_dl_addr(_IO_vtable_check, &di, &l, NULL) != 0 &&
							   l->l_ns != LM_ID_BASE))
			return;
	}

#else /* !SHARED */
	/* We cannot perform vtable validation in the static dlopen case
	   because FILE * handles might be passed back and forth across the
	   boundary.  Therefore, we disable checking in this case.  */
	if (__dlopen != NULL)
		return;
#endif

	__libc_fatal("Fatal error: glibc detected an invalid stdio handle\n");
}

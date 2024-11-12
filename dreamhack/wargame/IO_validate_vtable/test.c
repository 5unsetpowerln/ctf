static inline const struct _IO_jump_t *
IO_validate_vtable(const struct _IO_jump_t *vtable) {
	/* Fast path: The vtable pointer is within the __libc_IO_vtables
	   section.  */
	uintptr_t section_length =
		__stop___libc_IO_vtables - __start___libc_IO_vtables;
	const char *ptr = (const char *)vtable;
	uintptr_t offset = ptr - __start___libc_IO_vtables;
	if (__glibc_unlikely(offset >= section_length))
		/* The vtable pointer is not in the expected section.  Use the
		   slow path, which will terminate the process if necessary.  */
		_IO_vtable_check();
	return vtable;
}

// int _IO_str_overflow(_IO_FILE *fp, int c) {
// 	int flush_only = c == EOF;
// 	_IO_size_t pos;
// 	if (fp->_flags & _IO_NO_WRITES)
// 		return flush_only ? 0 : EOF;
// 	if ((fp->_flags & _IO_TIED_PUT_GET) &&
// 		!(fp->_flags & _IO_CURRENTLY_PUTTING)) {
// 		fp->_flags |= _IO_CURRENTLY_PUTTING;
// 		fp->_IO_write_ptr = fp->_IO_read_ptr;
// 		fp->_IO_read_ptr = fp->_IO_read_end;
// 	}
// 	pos = fp->_IO_write_ptr - fp->_IO_write_base;
// 	if (pos >= (_IO_size_t)(_IO_blen(fp) + flush_only)) {
// 		if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
// 			return EOF;
// 		else {
// 			char *new_buf;
// 			char *old_buf = fp->_IO_buf_base;
// 			size_t old_blen = _IO_blen(fp);
// 			_IO_size_t new_size = 2 * old_blen + 100;
// 			if (new_size < old_blen)
// 				return EOF;
// 			new_buf =
// 				(char *)(*((_IO_strfile *)fp)->_s._allocate_buffer)(new_size);

// #define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
// size_t old_blen = _IO_blen(fp);
// _IO_size_t new_size = 2 * old_blen + 100;
// if (new_size < old_blen)
// 	return EOF;

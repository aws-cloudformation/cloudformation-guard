cfn_guard_test : cfn_guard_test.c cfn_guard.h
	gcc cfn_guard_test.c -o cfn_guard_test -lcfn_guard_ffi -L../../target/debug

run : cfn_guard_test
	LD_LIBRARY_PATH=../../target/debug valgrind --track-origins=yes --log-file=valgrind-out.txt ./cfn_guard_test

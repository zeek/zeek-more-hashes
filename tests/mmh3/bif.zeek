# @TEST-EXEC: zeek -b Zeek::MoreHashes %INPUT >out
# @TEST-EXEC: btest-diff out

function my_assert(r: bool, msg: string) {
	if ( r )
		return;

	print msg;
	exit(1);
}

event zeek_init() &priority=0 {
	local h = mmh3_hash_init();
	mmh3_hash_update(h, "zeek");
	local r = mmh3_hash_finish(h);
	my_assert(r == 1898642774, fmt("expected 1898642774 got %s", r));
	print "\"zeek\"", r;
}

event zeek_init() &priority=-1 {
	local h = mmh3_hash_init(42);
	mmh3_hash_update(h, "zeek");
	local r = mmh3_hash_finish(h);
	my_assert(r == 162293119, fmt("expected 162293119 got %s", r));
	print "\"zeek\" with seed 42", r;
}

event zeek_init() &priority=-2 {
	local h = mmh3_hash_init(42);
	mmh3_hash_update(h, "z");
	mmh3_hash_update(h, "e");
	mmh3_hash_update(h, "e");
	mmh3_hash_update(h, "k");
	local r = mmh3_hash_finish(h);
	my_assert(r == 162293119, fmt("expected 162293119 got %s", r));
	print "\"zeek\" incremental with seed 42", r;
}

event zeek_init() &priority=-3 {
	local h = mmh3_hash_init();
	mmh3_hash_update(h, "z");
	mmh3_hash_update(h, "e");
	local r = mmh3_hash_finish(h);
	my_assert(r == 2907484762, fmt("expected 2907484762 got %s", r));
	print "\"ze\" incremental", r;
}

event zeek_init() &priority=-4 {
	local r = mmh3_hash("zeek");
	print "\"zeek\" oneshot", r;
	my_assert(r == 1898642774, fmt("expected 1898642774 got %s", r));
}

event zeek_init() &priority=-5 {
	local r = mmh3_hash("zeek", 42);
	print "\"zeek\" oneshot with seed 42", r;
	my_assert(r == 162293119, fmt("expected 162293119 got %s", r));
}

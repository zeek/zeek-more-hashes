# @TEST-EXEC: zeek -r $TRACES/get.trace $PACKAGE/mmh3.zeek %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: zeek-cut -m id.orig_h id.resp_h analyzers mime_type mmh3 < files.log > files.log.cut
# @TEST-EXEC: btest-diff files.log.cut

@load base/protocols/http

hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter) {
	print id, rec$fuid, rec$mmh3, type_name(rec$mmh3);
}

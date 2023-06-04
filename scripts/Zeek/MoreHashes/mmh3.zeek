@load base/frameworks/files

redef record Files::AnalyzerArgs += {
	## The seed to use for mmh3. Use :zeek:see:`Files::register_analyzer_add_callback`
	## for customization of this value.
	mmh3_seed: count &default = 0;
};

redef record Files::Info += {
	## The unsigned 32bit MurmurHash3 value.
	mmh3: count &log &optional;
};

event file_new(f: fa_file) {
	Files::add_analyzer(f, Files::ANALYZER_MMH3);
}

event file_hash(f: fa_file, kind: string, hash: string) {
	if ( kind == "MMH3" )
		f$info$mmh3 = to_count(hash);  # sad pandas
}


# @TEST-EXEC: zeek -NN Zeek::MoreFileHashes |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output

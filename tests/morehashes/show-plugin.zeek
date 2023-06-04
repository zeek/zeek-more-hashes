# @TEST-EXEC: zeek -NN Zeek::MoreHashes |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output

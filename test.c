

void buf_test() {
	int *buf = NULL;
	for (int i = 0; i < 100; i++) {
		buf_push(buf, i);
	}
	buf_free(buf);

	char *buf2 = NULL;
	for (int i = 0; i < 100; i++) {
		buf_push(buf2, '0' + i);
	}
	buf_free(buf2);
}


void lex_test() {
	init_stream("a1 23  ++= asdf  !=+==!/  323  + _23a  sd  + 13");
	expect_token(TOKEN_NAME);
	expect_token(TOKEN_INT);
	expect_token(TOKEN_PLUS);
	expect_token(TOKEN_PLUS);
	expect_token(TOKEN_ASSIGN);
	expect_token(TOKEN_NAME);
	expect_token(TOKEN_NEQ);
	expect_token(TOKEN_PLUS);
	expect_token(TOKEN_EQ);
	expect_token(TOKEN_NOT);
	expect_token(TOKEN_DIV);
	expect_token(TOKEN_INT);
	expect_token(TOKEN_PLUS);
	expect_token(TOKEN_NAME);
	expect_token(TOKEN_NAME);
	expect_token(TOKEN_PLUS);
	expect_token(TOKEN_INT);
	assert(is_token(TOKEN_EOF));
}


void intern_test() {
	char* s1 = intern_string("asdf");
	char* s2 = intern_string("zxcv");
	char* s3 = intern_string("wert");
	char* s4 = intern_string("asdf");
	char* s5 = intern_string("asd");
	char* s6 = intern_string("asdf!!");

	assert(s4 == s1);
	assert(s5 != s1);
	assert(s6 != s1);

}
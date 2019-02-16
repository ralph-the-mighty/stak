#define _CRT_SECURE_NO_WARNINGS

#ifdef _DEBUG
#include <Windows.h>
#endif


#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>


#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

//stretchy buffers


typedef struct BufHdr {
	size_t len;
	size_t cap;
	char buf[0];
} BufHdr;

void* buf__grow(const void*, size_t, size_t);

#define buf__hdr(b) ((BufHdr *)((char *)b - offsetof(BufHdr, buf)))
#define buf__fits(b, n) (buf_len(b) + (n) <= buf_cap(b))
#define buf__fit(b, n) (buf__fits(b, n) ? 0 : ((b) = buf__grow((b), buf_len(b) + n, sizeof(*(b)))))

#define buf_len(b) ((b) ? buf__hdr(b)->len : 0)
#define buf_cap(b) ((b) ? buf__hdr(b)->cap : 0)
#define buf_end(b) ((b) + buf_len(b))	
//#define buf_push(b, x) (buf__fit(b, 1), b[buf_len(b)] = (x), buf__hdr(b)->len++)
#define buf_push(b, ...) (buf__fit((b), 1), (b)[buf__hdr(b)->len++] = (__VA_ARGS__))
#define buf_free(b) ((b) ? free(buf__hdr(b)) : 0)


void *buf__grow(const void * buf, size_t new_len, size_t elem_size) {
	size_t new_cap = MAX(1 + 2 * buf_cap(buf), new_len);
	assert(new_len <= new_cap);
	size_t new_size = offsetof(BufHdr, buf) + new_cap * elem_size;
	BufHdr *new_hdr;
	if (buf) {
		new_hdr = realloc(buf__hdr(buf), new_size);
	} else {
		new_hdr = malloc(new_size);
		new_hdr->len = 0;
	}
	new_hdr->cap = new_cap;
	return new_hdr->buf;
}



typedef struct InternedString {
	char* string;
	size_t length;
} InternedString;

InternedString *interned_strings = NULL;



char* intern_string_range(char* start, char* one_past_end) {
	size_t size = one_past_end - start;
	for (InternedString *it = interned_strings; it != buf_end(interned_strings); it++) {
		if (it->length == size && strncmp(start, it->string, size) == 0) {
			return it->string;
		}
	}

	char* new_string = (char *)malloc(size + 1);
	strncpy(new_string, start, size);
	new_string[size] = 0;
	InternedString new_istring = { new_string, size };
	buf_push(interned_strings, new_istring);
	return new_string;
}


char* intern_string(char *string) {
	return intern_string_range(string, string + strlen(string));
}




char *keyword_var;
char *keyword_if;
char *keyword_else;
char *keyword_print;

void init_keywords() {
#define KEYWORD(s) keyword_##s = intern_string(#s)
	KEYWORD(var);
	KEYWORD(if);
	KEYWORD(else);
	KEYWORD(print);
#undef KEYWORD
}

typedef enum TokenKind {
	TOKEN_KIND_LAST_CHAR = 127,
	TOKEN_INT,
	TOKEN_NAME,
	TOKEN_EOF,
	TOKEN_KIND_SIZE
} TokenKind;


typedef struct Token {
	TokenKind kind;
	char* start;
	char* end;
	union {
		uint64_t intval;
		struct {
			char *stringval;
		};
	};
} Token;









void fatal(char* msg, ...) {
	va_list args;
	va_start(args, msg);
#ifdef _DEBUG
	char string[256];
	vsnprintf(string, sizeof(string), msg, args);
	string[sizeof(string) - 1] = 0;
	OutputDebugStringA(string);
	OutputDebugStringA("\n");
	exit(1);
#else
	printf("FATAL: ");
	vprintf(msg, args);
	printf("\n");
	va_end(args);
	exit(1);
#endif
}


size_t copy_token_kind_str(char* dest, size_t dest_size, TokenKind kind) {
	size_t n;
	switch (kind) {
	case TOKEN_INT:
		n = snprintf(dest, dest_size, "integer");
		break;
	case TOKEN_NAME:
		n = snprintf(dest, dest_size, "name");
		break;
	case TOKEN_EOF:
		n = snprintf(dest, dest_size, "EOF");
		break;
	}
	return n;
}


const char *token_kind_str(TokenKind kind) {
	static char buf[256];
	if (kind <= TOKEN_KIND_LAST_CHAR) {
		buf[0] = kind;
		buf[1] = 0;
	} else {
		size_t n = copy_token_kind_str(buf, sizeof(buf), kind);
		assert(n + 1 <= sizeof(buf));
	}
	return buf;
}



Token token;
char* stream;

// 0xdeadbeef01231
//
// dec: 0b1231412
// hex: 0xdeadbeef, 0123456789ABCDEF
// bin: 0b1011011011110001110101


int table[256] = {
	['0'] = 0,
	['1'] = 1,
	['2'] = 2,
	['3'] = 3,
	['4'] = 4,
	['5'] = 5,
	['6'] = 6,
	['7'] = 7,
	['8'] = 8,
	['9'] = 9,
	['a'] = 10,['A'] = 10,
	['b'] = 11,['B'] = 11,
	['c'] = 12,['C'] = 12,
	['d'] = 13,['D'] = 13,
	['e'] = 14,['E'] = 14,
	['f'] = 15,['F'] = 15
};




int scan_int() {
	int val = 0;
	int base = 10;
	if (*stream == '0') {
		stream++;
		if (tolower(*stream) == 'x') {
			//hexadecimal
			base = 16;
			stream++;
		} else if (tolower(*stream) == 'b') {
			base = 2;
			stream++;
		}
	}

	while (*stream == '0' || table[*stream] != 0) {
		unsigned char digit = table[*stream];
		if (digit > base) {
			fatal("malformed integer: expected base %d, but got digit %c", base, *stream);
		}
		val *= base;
		val += digit;
		stream++;
	}
	return val;
}



void next_token() {

	while (isspace(*stream)) {
		stream++;
	}

	switch (*stream) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	{
		token.kind = TOKEN_INT;
		token.intval = scan_int();
	} break;
	case 'a': case 'b': case 'c': case 'd':	case 'e': case 'f':	case 'g': case 'h':	case 'i': case 'j':
	case 'k': case 'l': case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':	case 's': case 't':
	case 'u': case 'v':	case 'w': case 'x':	case 'y': case 'z':
	case 'A': case 'B':	case 'C': case 'D':	case 'E': case 'F':	case 'G': case 'H':	case 'I': case 'J':
	case 'K': case 'L':	case 'M': case 'N':	case 'O': case 'P':	case 'Q': case 'R':	case 'S': case 'T':
	case 'U': case 'V':	case 'W': case 'X':	case 'Y': case 'Z':	case '_':
	{
		token.kind = TOKEN_NAME;
		char* start = stream++;
		while (isalnum(*stream) || *stream == '_') {
			stream++;
		}
		char* end = stream;
		token.stringval = intern_string_range(start, end);
	} break;

	case 0:
	{
		token.kind = TOKEN_EOF;
	} break;

	default:
	{
		token.kind = *stream++;
	} break;
	}
}


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

void expect_token(TokenKind kind) {
	if (token.kind == kind) {
		next_token();
	} else {
		fatal("expected %s, got %s", token_kind_str(kind), token_kind_str(token.kind));
	}
}

void expect_keyword(char* keyword) {
	if (!(token.kind == TOKEN_NAME && token.stringval == keyword)) {
		fatal("expected keyword %s but got %s", keyword, token_kind_str(token.kind));
	} else {
		next_token();
	}
}

bool is_token(TokenKind kind) {
	return token.kind == kind;
}

bool is_keyword(char* keyword) {
	return (token.kind == TOKEN_NAME && token.stringval == keyword);
}


int match_token(TokenKind kind) {
	if (token.kind == kind) {
		next_token();
		return true;
	} else {
		return false;
	}
}



char** sym_table;


void new_var(char* name) {
	for (char * it = sym_table; it <= buf_end(sym_table); it++) {
		if (name == it) {
			fatal("var %s already declared", name);
		}
	}
	buf_push(sym_table, name);
}


int lookup_var(char* name) {
	for (int i = 0; i < buf_len(sym_table); i++) {
		if (name == sym_table[i]) {
			return i;
		}
	}
	fatal("var %s not declared", name);
}


typedef enum OpCode {
	ADD,
	SUB,
	DIV,
	MUL,
	NEG,
	LIT,
	LOAD,
	STORE,
	PRINT,
	HALT
} OpCode;




int32_t *code;



void parse_expr(void);


void parse_expr4() {
	if (is_token(TOKEN_INT)) {
		buf_push(code, LIT);
		buf_push(code, token.intval);
		next_token();
	} else if (is_token(TOKEN_NAME)) {
		buf_push(code, LOAD);
		buf_push(code, lookup_var(token.stringval));
		next_token();
	} else if (is_token('(')) {
		next_token();
		parse_expr();
		expect_token(')');
	}
}


void parse_expr3() {
	if (is_token('-')) {
		next_token();
		parse_expr4();
		buf_push(code, NEG);
	} else {
		parse_expr4();
	}
}



void parse_expr2() {
	parse_expr3();
	while (is_token('*') || is_token('/')) {
		TokenKind op = token.kind;
		next_token();
		if (op == '*') {
			parse_expr2();
			buf_push(code, MUL);
		} else {
			parse_expr2();
			buf_push(code, DIV);
		}
	}
}



void parse_expr1() {
	parse_expr2();
	while (is_token('+') || is_token('-')) {
		TokenKind op = token.kind;
		next_token();
		if (op == '+') {
			parse_expr2();
			buf_push(code, ADD);
		} else {
			parse_expr2();
			buf_push(code, SUB);
		}
	}
}


void parse_expr() {
	parse_expr1();
}



void parse_decl() {
	expect_keyword(keyword_var);
	if (is_token(TOKEN_NAME)) {
		new_var(token.stringval);
		next_token();
	} else {
		fatal("name must follow var in delaration");
	}
}


void parse_decls() {
	while (is_keyword(keyword_var)) {
		parse_decl();
	}
}


void parse_statement_assign() {
	if (is_token(TOKEN_NAME)) {
		char* varname = token.stringval;
		next_token();
		expect_token('=');
		parse_expr();
		buf_push(code, STORE);
		buf_push(code, lookup_var(varname));
	} else {
		fatal("expected variable assignment to start with a name");
	}
}


void parse_statement_print() {
	expect_keyword(keyword_print);
	parse_expr();
	buf_push(code, PRINT);
}


void parse_statements() {
	//TODO: maybe don't assume here that EOF always follows the statements
	while (!is_token(TOKEN_EOF)) {
		if (is_keyword(keyword_print)) {
			parse_statement_print();
		} else if (is_token(TOKEN_NAME)) {
			parse_statement_assign();
		} else {
			fatal("expected either a print statement or an assignment");
		}
	}
	assert(is_token(TOKEN_EOF));
	next_token();
}

void parse_program() {
	parse_decls();
	parse_statements();
}



void init_stream(char *string) {
	stream = string;
	next_token();
}


void compile(char* string) {
	init_stream(string);
	parse_program();
	buf_push(code, HALT);
}




int32_t check_runtime_stack_exception(const int *code) {
	enum { MAX_STACK = 1024 };
	int32_t top = 0;
	for (;;) {
		int32_t op = *code++;
		switch (op) {
		case ADD:
		case SUB:
		case MUL:
		case DIV:
			top--;
		case LIT:
			top++;
			*code++;
		case HALT:
			return (top > 0 && top < MAX_STACK);
		default:
			printf("vm_exec: illegal opcode");
			exit(0);
			return 0;
		}
	}
}




char* disassemble(int* buffer) {
	static char text[1024 * 4];
	char* cursor = text;
	for (OpCode* it = buffer; it < buf_end(buffer); it++) {
		switch (*it) {
		case ADD:
			cursor += sprintf(cursor, "ADD\n");
			break;
		case SUB:
			cursor += sprintf(cursor, "SUB\n");
			break;
		case MUL:
			cursor += sprintf(cursor, "MUL\n");
			break;
		case DIV:
			cursor += sprintf(cursor, "DIV\n");
			break;
		case NEG:
			cursor += sprintf(cursor, "NEG\n");
			break;
		case LIT:
			cursor += sprintf(cursor, "LIT ");
			cursor += sprintf(cursor, "%d\n", *(++it));
			break;
		case LOAD:
			cursor += sprintf(cursor, "LOAD ");
			cursor += sprintf(cursor, "%d\n", *(++it));
			break;
		case STORE:
			cursor += sprintf(cursor, "STORE ");
			cursor += sprintf(cursor, "%d\n", *(++it));
			break;
		case PRINT:
			cursor += sprintf(cursor, "PRINT\n");
			break;
		case HALT:
			cursor += sprintf(cursor, "HALT\n");
			break;

		default:
			fatal("attempted to disassemble non-esistent opcode %d", *it);
		}
	}
	if (cursor != text) {
		*(cursor - 1) = 0;
	}
	return text;
}




void vm_exec(const int *code) {

#define POP() \
    (*--top)
#define PUSH(x) \
    (*top++ = (x))
#define POPS(n) \
    assert(top - stack >= (n))
#define PUSHES(n) \
    assert(top + (n) <= stack + MAX_STACK)

	enum { MAX_STACK = 1024 };
	int32_t stack[MAX_STACK];

	enum { MAX_VARS = 1024 };
	int32_t store[MAX_STACK];

	int32_t *top = stack;
	for (;;) {
		int32_t op = *code++;
		switch (op) {
		case ADD: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left + right);
			break;
		}
		case SUB: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left - right);
			break;
		}
		case MUL: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left * right);
			break;
		}
		case DIV: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left / right);
			break;
		}
		case NEG: {
			POPS(2);
			int32_t val = POP();
			PUSHES(1);
			PUSH(-val);
			break;
		}
		case LIT: {
			PUSHES(1);
			PUSH(*code++);
			break;
		}
		case LOAD: {
			PUSHES(1);
			PUSH(store[*code++]);
			break;
		}
		case STORE: {
			POPS(1);
			store[*code++] = POP();
			break;
		}
		case PRINT: {
			POPS(1);
			printf("print: %d", POP());
			break;
		}
		case HALT: {
			return;
		}
		default:
			printf("vm_exec: illegal opcode");
			exit(0);
			return 0;
		}
	}

#undef POP
#undef PUSH
#undef POPS
#undef PUSHES
}



void lex_test() {
	init_stream("a1 23  + asdf  +  323  + _23a  sd  + 13");
	expect_token(TOKEN_NAME);
	expect_token(TOKEN_INT);
	expect_token('+');
	expect_token(TOKEN_NAME);
	expect_token('+');
	expect_token(TOKEN_INT);
	expect_token('+');
	expect_token(TOKEN_NAME);
	expect_token(TOKEN_NAME);
	expect_token('+');
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



int main(int argc, char **argv) {
	init_keywords();

	buf_test();
	lex_test();
	intern_test();
	char* source;
	if (load_file("C:\\Users\\JoshPC\\projects\\Random_Projects\\ion\\TextFile1.txt", &source) < 0) {
		fatal("Could not load code");
	}
	compile(source);
	vm_exec(code);
}
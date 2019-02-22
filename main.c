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

#include "common.c"






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
char *keyword_while;
char *keyword_true;
char *keyword_false;

void init_keywords() {
#define KEYWORD(s) keyword_##s = intern_string(#s)
	KEYWORD(var);
	KEYWORD(if);
	KEYWORD(else);
	KEYWORD(print);
	KEYWORD(while);
	KEYWORD(true);
	KEYWORD(false);
#undef KEYWORD
}

typedef enum TokenKind {
	TOKEN_INT,
	TOKEN_NAME,



	//mul associativity
	TOKEN_FIRST_MUL,
	TOKEN_MUL = TOKEN_FIRST_MUL,
	TOKEN_DIV,
	TOKEN_MOD,
	TOKEN_AND,
	TOKEN_LAST_MUL = TOKEN_AND,


	//add associativity
	TOKEN_FIRST_ADD,
	TOKEN_PLUS = TOKEN_FIRST_ADD,
	TOKEN_MINUS,
	TOKEN_OR,
	TOKEN_XOR,
	TOKEN_LAST_ADD = TOKEN_XOR,

	//cmp associativity
	TOKEN_FIRST_CMP,
	TOKEN_LT = TOKEN_FIRST_CMP,
	TOKEN_GT,
	TOKEN_LTE,
	TOKEN_GTE,
	TOKEN_EQ,
	TOKEN_NEQ,
	TOKEN_LAST_CMP = TOKEN_NEQ,

	TOKEN_OR_OR,
	TOKEN_AND_AND,
	TOKEN_ASSIGN,
	TOKEN_NOT,
	TOKEN_BIT_NOT,

	//grouping tokens
	TOKEN_LPAREN,
	TOKEN_RPAREN,
	TOKEN_LBRACE,
	TOKEN_RBRACE,
	TOKEN_COMMA,
	
	TOKEN_EOF,
} TokenKind;


const char* token_string_map[] = {
	[TOKEN_INT] = "int",
	[TOKEN_NAME] = "name",
	[TOKEN_PLUS] = "+",
	[TOKEN_MINUS] = "-",
	[TOKEN_MUL] = "*",
	[TOKEN_DIV] = "/",
	[TOKEN_MOD] = "%",
	[TOKEN_NOT] = "!",
	[TOKEN_AND] = "&",
	[TOKEN_OR] = "|",
	[TOKEN_XOR] = "^",
	[TOKEN_LT] = "<",
	[TOKEN_GT] = ">",
	[TOKEN_LTE] = "<=",
	[TOKEN_GTE] = ">=",
	[TOKEN_EQ] = "==",
	[TOKEN_NEQ] = "!=",
	[TOKEN_OR_OR] = "||",
	[TOKEN_AND_AND] = "&&",
	[TOKEN_BIT_NOT] = "~",
	[TOKEN_ASSIGN] = "=",
	[TOKEN_LPAREN] = "(",
	[TOKEN_RPAREN] = ")",
	[TOKEN_LBRACE] = "{",
	[TOKEN_RBRACE] = "}",
	[TOKEN_COMMA] = ",",
	[TOKEN_EOF] = "EOF",
};



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
	OutputDebugStringA("FATAL: ");
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
	return token_string_map[kind];
}



Token token;
char* stream;

// 0xdeadbeef01231
//
// dec: 0b1231412
// hex: 0xdeadbeef, 0123456789ABCDEF
// bin: 0b1011011011110001110101


int digit_table[256] = {
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

	while (*stream == '0' || digit_table[*stream] != 0) {
		unsigned char digit = digit_table[*stream];
		if (digit > base) {
			fatal("malformed integer: expected base %d, but got digit %c", base, *stream);
		}
		val *= base;
		val += digit;
		stream++;
	}
	return val;
}

#define CASE1(x, k) case x: token.kind = k; \
						stream++;           \
						break;              
#define CASE2(x1, k1, x2, k2) case x1:           \
						if(*++stream == x2) {    \
							token.kind = k2;     \
							stream++;            \
						} else {                 \
							token.kind = k1;     \
						}						 \
						break;


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

	CASE1('+', TOKEN_PLUS)
	CASE1('-', TOKEN_MINUS)
	CASE1('*', TOKEN_MUL)
	CASE1('/', TOKEN_DIV)
	CASE1('%', TOKEN_MOD)
	CASE1('^', TOKEN_XOR)
	CASE1('~', TOKEN_BIT_NOT)
	CASE2('!', TOKEN_NOT, '=', TOKEN_NEQ)
	CASE2('<', TOKEN_LT, '=', TOKEN_LTE)
	CASE2('>', TOKEN_GT, '=', TOKEN_GTE)
	CASE2('=', TOKEN_ASSIGN, '=', TOKEN_EQ)
	CASE2('&', TOKEN_AND, '&', TOKEN_AND_AND)
	CASE2('|', TOKEN_OR, '|', TOKEN_OR_OR)
	CASE1('(', TOKEN_LPAREN)
	CASE1(')', TOKEN_RPAREN)
	CASE1('{', TOKEN_LBRACE)
	CASE1('}', TOKEN_RBRACE)
	CASE1(',', TOKEN_COMMA)
			   
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

#undef CASE1
#undef CASE2




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

bool match_token(TokenKind kind) {
	if (token.kind == kind) {
		next_token();
		return true;
	} else {
		return false;
	}
}

bool is_keyword(char* keyword) {
	return (token.kind == TOKEN_NAME && token.stringval == keyword);
}

bool match_keyword(char*keyword) {
	if (token.kind == TOKEN_NAME && token.stringval == keyword) {
		next_token();
		return true;
	} else {
		return false;
	}
}

bool is_add_token(TokenKind kind) {
	return (kind >= TOKEN_FIRST_ADD) && (kind <= TOKEN_LAST_ADD);
}

bool is_mul_token(TokenKind kind) {
	return (kind >= TOKEN_FIRST_MUL) && (kind <= TOKEN_LAST_MUL);
}

bool is_cmp_token(TokenKind kind) {
	return (kind >= TOKEN_FIRST_CMP) && (kind <= TOKEN_LAST_CMP);
}



#define assert_token(x) (assert(token.kind == (x)));
#define assert_keyword(kw) (assert(token.kind == TOKEN_NAME && token.stringval == (kw)));



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
	MUL,
	DIV,
	MOD,
	NEG,
	LIT,
	LT,
	LTE,
	GT,
	GTE,
	EQ,
	NEQ,
	BIT_AND,
	BIT_OR,
	BIT_NEG,
	BIT_XOR,
	BOOL_AND,
	BOOL_OR,
	BOOL_NOT,
	JEZ,
	JMP,
	LOAD,
	STORE,
	PRINT,
	HALT,
	NOP,
} OpCode;




int32_t *code;



void parse_expr(void);


void parse_expr_val() {
	if (is_token(TOKEN_INT)) {
		buf_push(code, LIT);
		buf_push(code, token.intval);
		next_token();
	} else if (is_token(TOKEN_NAME)) {
		if (token.stringval == keyword_true) {
			buf_push(code, LIT);
			buf_push(code, 1);
		} else if (token.stringval == keyword_false) {
			buf_push(code, LIT);
			buf_push(code, 0);
		} else {
			buf_push(code, LOAD);
			buf_push(code, lookup_var(token.stringval));
		}
		next_token();
	} else if (match_token(TOKEN_LPAREN)) {
		parse_expr();
		expect_token(TOKEN_RPAREN);
	}
}


void parse_expr_unary() {
	if (match_token(TOKEN_MINUS)) {
		parse_expr_val();
		buf_push(code, NEG);
	} else if (match_token(TOKEN_NOT)) {
		parse_expr_val();
		buf_push(code, BOOL_NOT);
	} else {
		parse_expr_val();
	}
}



void parse_expr_mul() {
	parse_expr_unary();
	while (is_mul_token(token.kind)) {
		TokenKind op = token.kind;
		next_token();
		parse_expr_unary();
		switch (op) {
			case TOKEN_MUL:
				buf_push(code, MUL);
				break;
			case TOKEN_DIV:
				buf_push(code, DIV);
				break;
			case TOKEN_MOD:
				buf_push(code, MOD);
				break;
			case TOKEN_AND:
				buf_push(code, BIT_AND);
				break;
			default:
				assert(0);
				break;
		}
	}
}



void parse_expr_add() {
	parse_expr_mul();
	while (is_add_token(token.kind)) {
		TokenKind op = token.kind;
		next_token();
		parse_expr_mul();
		switch (op) {
		case TOKEN_PLUS:
			buf_push(code, ADD);
			break;
		case TOKEN_MINUS:
			buf_push(code, SUB);
			break;
		case TOKEN_OR:
			buf_push(code, BIT_OR);
			break;
		case TOKEN_XOR:
			buf_push(code, BIT_XOR);
			break;
		default:
			assert(0);
			break;
		}
	}
}

void parse_expr_cmp() {
	parse_expr_add();
	while (is_cmp_token(token.kind)) {
		TokenKind op = token.kind;
		next_token();
		parse_expr_add();
		switch (op) {
		case TOKEN_LT:
			buf_push(code, LT);
			break;
		case TOKEN_LTE:
			buf_push(code, LTE);
			break;
		case TOKEN_GT:
			buf_push(code, GT);
			break;
		case TOKEN_GTE:
			buf_push(code, GTE);
			break;
		case TOKEN_EQ:
			buf_push(code, EQ);
			break;
		case TOKEN_NEQ:
			buf_push(code, NEQ);
			break;
		default:
			assert(0);
			break;
		}
	}
}


void parse_expr_and() {
	parse_expr_cmp();
	while (match_token(TOKEN_AND_AND)) {
		parse_expr_cmp();
		buf_push(code, BOOL_AND);
	}
}

void parse_expr_or() {
	parse_expr_and();
	while (match_token(TOKEN_OR_OR)) {
		parse_expr_and();
		buf_push(code, BOOL_OR);
	}
}


void parse_expr() {
	parse_expr_or();
}


void parse_var_decl() {
	if (is_token(TOKEN_NAME)) {
		new_var(token.stringval);
		next_token();
	} else {
		fatal("expected variable name");
	}
}

void parse_decl() {
	expect_keyword(keyword_var);
	parse_var_decl();
	while (match_token(TOKEN_COMMA)) {
		parse_var_decl();
	}
}


void parse_decls() {
	while (is_keyword(keyword_var)) {
		parse_decl();
	}
}


// statements
int jump_forward(OpCode op) {
	buf_push(code, op);
	int index = buf_len(code);
	buf_push(code, NOP);
	return index;
}

void patch_jump_here(int loc) {
	code[loc] = buf_len(code) - loc;
}

void jump_back(OpCode op, int loc) {
	buf_push(code, op);
	buf_push(code, loc - buf_len(code));
}

void parse_stmt();

void parse_stmt_assign() {
	assert_token(TOKEN_NAME);
	char* varname = token.stringval;
	next_token();
	expect_token(TOKEN_ASSIGN);
	parse_expr();
	buf_push(code, STORE);
	buf_push(code, lookup_var(varname));
}


void parse_stmt_while() {
	int compare_loc = buf_len(code);
	parse_expr();
	int else_jump_loc = jump_forward(JEZ);
	parse_stmt();
	jump_back(JMP, compare_loc);
	patch_jump_here(else_jump_loc);
}


void parse_stmt_print() {
	parse_expr();
	buf_push(code, PRINT);
}


void parse_stmt_if() {
	parse_expr();
	int else_jump_loc = jump_forward(JEZ);
	parse_stmt();
	if (match_keyword(keyword_else)) {
		int end_jump_loc = jump_forward(JMP);
		patch_jump_here(else_jump_loc);
		parse_stmt();
		patch_jump_here(end_jump_loc);
	} else {
		patch_jump_here(else_jump_loc);
	}
}


void parse_stmt_block() {
	parse_decls();
	while (!is_token(TOKEN_EOF) && !is_token(TOKEN_RBRACE)) {
		parse_stmt();
	}
	expect_token(TOKEN_RBRACE);
}


void parse_stmt() {
	if (match_keyword(keyword_if)) {
		parse_stmt_if();
	} else if (match_keyword(keyword_print)) {
		parse_stmt_print();
	} else if (match_keyword(keyword_while)) {
		parse_stmt_while();
	} else if (is_token(TOKEN_NAME)) {
		parse_stmt_assign();
	} else if (match_token(TOKEN_LBRACE)) {
		parse_stmt_block();
	} else {
		assert(0);
	}
}


void parse_program() {
	parse_stmt();
	expect_token(TOKEN_EOF);
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




#define CASE(x) case x: \
					buf_printf(output, #x); \
					buf_printf(output, "\n"); \
					break;
#define CASE_OP(x) case x: \
					buf_printf(output, #x); \
					buf_printf(output, " %d\n", *(++it)); \
					break;


char* disassemble(int* code_buf) {
	char *output = NULL;
	for (OpCode* it = code_buf; it < buf_end(code_buf); it++) {
		switch (*it) {
			CASE(ADD)
			CASE(SUB)
			CASE(MUL)
			CASE(DIV)
			CASE(NEG)
			CASE(MOD)
			CASE(BIT_NEG)
			CASE(BIT_AND)
			CASE(BIT_OR)
			CASE(BIT_XOR)
			CASE(BOOL_NOT)
			CASE(BOOL_OR)
			CASE(BOOL_AND)
			CASE(LT)
			CASE(LTE)
			CASE(GT)
			CASE(GTE)
			CASE(EQ)
			CASE(NEQ)
			CASE_OP(JEZ)
			CASE_OP(JMP)
			CASE_OP(LIT)
			CASE_OP(LOAD)
			CASE_OP(STORE)
			CASE(PRINT)
			CASE(HALT)

		default:
			fatal("attempted to disassemble non-esistent opcode %d", *it);
			break;
		}
	}
	return output;
}

#undef CASE
#undef CASE_OP



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
		//arithmetic
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
			POPS(1);
			int32_t val = POP();
			PUSHES(1);
			PUSH(-val);
			break;
		}
		case MOD: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left % right);
			break;
		}
		//bitwise
		case BIT_AND: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left % right);
			break;
		}
		case BIT_OR: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left | right);
			break;
		}
		case BIT_NEG: {
			POPS(1);
			int32_t val = POP();
			PUSHES(1);
			PUSH(val);
			break;
		}
		case BIT_XOR: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left ^ right);
			break;
		}
		//comparative
		case LT: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left < right);
			break;
		}
		case LTE: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left <= right);
			break;
		}
		case GT: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left > right);
			break;
		}
		case GTE: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left >= right);
			break;
		}
		case EQ: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left == right);
			break;
		}
		case NEQ: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left != right);
			break;
		}
		//boolean
		case BOOL_AND: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left && right);
			break;
		}
		case BOOL_OR: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left || right);
			break;
		}
		case BOOL_NOT: {
			POPS(1);
			int32_t val = POP();
			PUSHES(1);
			PUSH(!val);
			break;
		}		
		//flow control
		case JEZ: {
			if (POP() == 0)
				code += *code;
			else
				code++;
			break;
		}
		case JMP: {
			code += *code;
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
			printf("%d\n", POP());
			break;
		}
		case HALT: {
			return;
			break;
		}

		case NOP: {
			//do nothing;
			break;
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




#include "test.c"

char* disassembly;

int main(int argc, char **argv) {
	init_keywords();

	buf_test();
	lex_test();
	intern_test();
	char* source;
	if (load_file("C:\\Users\\JoshPC\\projects\\Random_Projects\\stak\\test.stak", &source) < 0) {
		fatal("Could not load code");
	}

	compile(source);
	disassembly = disassemble(code);
 	vm_exec(code);
	buf_free(disassembly);
}


/*
{
print 1 | 2
print 3 ^ 4
print 5 && 6
print 7 || 8
print 9 % 10
print 11 ^ 12
print 13 & 14
print 15 == 16
print 17 < 18
print 19 > 20
print 21 <= 22
print 23 >= 24
print !25
print -26
print 27 != 28
}
*/
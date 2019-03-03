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










char *keyword_var;
char *keyword_if;
char *keyword_else;
char *keyword_print;
char *keyword_while;
char *keyword_true;
char *keyword_false;
char *keyword_return;
char *keyword_func;

char *first_keyword;
char *last_keyword;

char *name_main;


void init_keywords_and_names() {
#define KEYWORD(s) keyword_##s = intern_string(#s)
	KEYWORD(var);
	first_keyword = keyword_var;
	KEYWORD(if);
	KEYWORD(else);
	KEYWORD(print);
	KEYWORD(while);
	KEYWORD(true);
	KEYWORD(false);
	KEYWORD(return);
	KEYWORD(func);
	last_keyword = keyword_func;
#undef KEYWORD

#define NAME(s) name_##s = intern_string(#s)
	NAME(main);
#undef NAME
}

bool is_keyword_name() {
	//FILL ME IN
	assert(0);
	return false;
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
// dec: 1231412
// hex: 0xdeadbeef, 0x0123456789ABCDEF
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
	restart:
	//skip whitespace
	while (isspace(*stream)) {
		stream++;
	}


	//skip comments
	if (*stream == '/' && *(stream + 1) == '*') {
		stream += 2;
		for (;;) {
			if (*stream == '*' && *(stream + 1) == '/') {
				stream += 2;
				goto restart;
			}
			stream++;
		}
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










typedef enum OpCode {
	OP_ADD,
	OP_SUB,
	OP_MUL,
	OP_DIV,
	OP_MOD,
	OP_NEG,
	OP_LIT,
	OP_LT,
	OP_LTE,
	OP_GT,
	OP_GTE,
	OP_EQ,
	OP_NEQ,
	OP_BIT_AND,
	OP_BIT_OR,
	OP_BIT_NEG,
	OP_BIT_XOR,
	OP_BOOL_AND,
	OP_BOOL_OR,
	OP_BOOL_NOT,
	OP_JEZ,
	OP_JMP,
	OP_LOAD,
	OP_STORE,
	OP_PRINT,
	OP_HALT,
	OP_NOP,

	//function stuff
	OP_RETURN,
	OP_ALLOC,
	OP_CLEAR,
	OP_CALL,
	OP_LOCAL,
	OP_ARG,
} OpCode;




int32_t *code;

void emit(OpCode op) {
	buf_push(code, op);
}



char** local_sym_table;


void new_sym(char* name) {
	for (char * it = local_sym_table; it <= buf_end(local_sym_table); it++) {
		if (name == it) {
			fatal("var %s already declared", name);
		}
	}
	buf_push(local_sym_table, name);
}


int lookup_sym(char* name) {
	for (int i = 0; i < buf_len(local_sym_table); i++) {
		if (name == local_sym_table[i]) {
			return i;
		}
	}
	fatal("var %s not declared", name);
}





//functions

typedef struct Func {
	char *name;
	size_t num_params;
	size_t num_locals;
	size_t loc;
} Func;

Func *funcs;

Func new_func_here(char* name) {
	for (Func* it = funcs; it < buf_end(funcs); it++) {
		if (it->name == name) {
			fatal("func %s already defined", name);
		}
	}
	Func func;
	func.name = name;
	func.loc = buf_len(code);
	func.num_params = 0;
	func.num_locals = 0;
	buf_push(funcs, func);
	return func;
}


Func* lookup_func(char *name) {
	for (Func* it = funcs; it < buf_end(funcs); it++) {
		if (it->name == name) {
			return it;
		}
	}
	return NULL;
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

TokenKind lookahead() {
	Token t = token;
	char* bookmark = stream;
	next_token();
	TokenKind kind = token.kind;
	token = t;
	stream = bookmark;
	return kind;
}



#define assert_token(x) (assert(token.kind == (x)));
#define assert_keyword(kw) (assert(token.kind == TOKEN_NAME && token.stringval == (kw)));


//parsing
void parse_expr(void);



void parse_params() {
	parse_expr();
	while (match_token(TOKEN_COMMA)) {
		parse_expr();
	}
}


void parse_expr_val() {
	if (is_token(TOKEN_INT)) {
		emit(OP_LIT);
		emit(token.intval);
		next_token();
	} else if (is_token(TOKEN_NAME)) {
		if (token.stringval == keyword_true) {
			emit(OP_LIT);
			emit(1);
			next_token();
		} else if (token.stringval == keyword_false) {
			emit(OP_LIT);
			emit(0);
			next_token();
		} else {
			//check to see if name is variable or function call
			char* name = token.stringval;
			next_token();
			if (match_token(TOKEN_LPAREN)) {
				//TODO: functions with parameters
				//parse_params();
				expect_token(TOKEN_RPAREN);
				Func* func = lookup_func(name);
				if (!func) {
					fatal("cannot call function %s;  function has not been declared.", name);
				}
				emit(OP_CALL);
				emit(func->loc);
			} else {
				emit(OP_LOAD);
				emit(lookup_sym(name));
			}
		}
	} else if (match_token(TOKEN_LPAREN)) {
		parse_expr();
		expect_token(TOKEN_RPAREN);
	}
}


void parse_expr_unary() {
	if (match_token(TOKEN_MINUS)) {
		parse_expr_val();
		emit(OP_NEG);
	} else if (match_token(TOKEN_NOT)) {
		parse_expr_val();
		emit(OP_BOOL_NOT);
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
			emit(OP_MUL);
			break;
		case TOKEN_DIV:
			emit(OP_DIV);
			break;
		case TOKEN_MOD:
			emit(OP_MOD);
			break;
		case TOKEN_AND:
			emit(OP_BIT_AND);
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
			emit(OP_ADD);
			break;
		case TOKEN_MINUS:
			emit(OP_SUB);
			break;
		case TOKEN_OR:
			emit(OP_BIT_OR);
			break;
		case TOKEN_XOR:
			emit(OP_BIT_XOR);
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
			emit(OP_LT);
			break;
		case TOKEN_LTE:
			emit(OP_LTE);
			break;
		case TOKEN_GT:
			emit(OP_GT);
			break;
		case TOKEN_GTE:
			emit(OP_GTE);
			break;
		case TOKEN_EQ:
			emit(OP_EQ);
			break;
		case TOKEN_NEQ:
			emit(OP_NEQ);
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
		emit(OP_BOOL_AND);
	}
}

void parse_expr_or() {
	parse_expr_and();
	while (match_token(TOKEN_OR_OR)) {
		parse_expr_and();
		emit(OP_BOOL_OR);
	}
}


void parse_expr() {
	parse_expr_or();
}


void parse_var_decl() {
	if (is_token(TOKEN_NAME)) {
		new_sym(token.stringval);
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


void parse_local_decls() {
	while (is_keyword(keyword_var)) {
		parse_decl();
	}
}



int jump_forward(OpCode op) {
	emit(op);
	int index = buf_len(code);
	emit(OP_NOP);
	return index;
}

void patch_jump_here(int loc) {
	code[loc] = buf_len(code) - loc;
}

void jump_back(OpCode op, int loc) {
	emit(op);
	emit(loc - buf_len(code));
}




// statements
void parse_stmt();

void parse_stmt_assign() {
	assert_token(TOKEN_NAME);
	char* varname = token.stringval;
	next_token();
	expect_token(TOKEN_ASSIGN);
	parse_expr();
	emit(OP_STORE);
	emit(lookup_sym(varname));
}


void parse_stmt_while() {
	int compare_loc = buf_len(code);
	parse_expr();
	int else_jump_loc = jump_forward(OP_JEZ);
	parse_stmt();
	jump_back(OP_JMP, compare_loc);
	patch_jump_here(else_jump_loc);
}


void parse_stmt_print() {
	parse_expr();
	emit(OP_PRINT);
}


void parse_stmt_if() {
	parse_expr();
	int else_jump_loc = jump_forward(OP_JEZ);
	parse_stmt();
	if (match_keyword(keyword_else)) {
		int end_jump_loc = jump_forward(OP_JMP);
		patch_jump_here(else_jump_loc);
		parse_stmt();
		patch_jump_here(end_jump_loc);
	} else {
		patch_jump_here(else_jump_loc);
	}
}


void parse_stmt_block() {
	parse_local_decls();
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
	} else if (match_token(TOKEN_LBRACE)) {
		parse_stmt_block();
	} else {
		assert_token(TOKEN_NAME);
		if (lookahead() == TOKEN_ASSIGN) {
			parse_stmt_assign();
		} else {
			parse_expr();
		}
	}
}


void parse_func_decl() {
	assert_token(TOKEN_NAME);
	char* name = token.stringval;
	next_token();
	new_func_here(name);
	expect_token(TOKEN_LPAREN);
	expect_token(TOKEN_RPAREN);
	parse_stmt();
	emit(OP_RETURN);
}



void parse_decls() {
	while (match_keyword(keyword_func)) {
		parse_func_decl();
	}
}


void parse_program() {
	emit(OP_CALL);
	int main_call_loc = buf_len(code);
	emit(OP_NOP);
	emit(OP_HALT);
	parse_decls();
	expect_token(TOKEN_EOF);

	Func* func_main = lookup_func(name_main);
	if (!func_main) {
		fatal("cannot compile program without main func defined");
	}
	code[main_call_loc] = func_main->loc;
}



void init_stream(char *string) {
	stream = string;
	next_token();
}


void compile(char* string) {
	init_stream(string);
	parse_program();
}




#define CASE(x) case x: \
					buf_printf(output, (#x)+3); \
					buf_printf(output, "\n"); \
					break;
#define CASE_OP(x) case x: \
					buf_printf(output, (#x)+3); \
					buf_printf(output, " %d\n", *(++it)); \
					break;


char* disassemble(int* code_buf) {
	char *output = NULL;
	for (OpCode* it = code_buf; it < buf_end(code_buf); it++) {
		switch (*it) {
			CASE(OP_ADD)
			CASE(OP_SUB)
			CASE(OP_MUL)
			CASE(OP_DIV)
			CASE(OP_NEG)
			CASE(OP_MOD)
			CASE(OP_BIT_NEG)
			CASE(OP_BIT_AND)
			CASE(OP_BIT_OR)
			CASE(OP_BIT_XOR)
			CASE(OP_BOOL_NOT)
			CASE(OP_BOOL_OR)
			CASE(OP_BOOL_AND)
			CASE(OP_LT)
			CASE(OP_LTE)
			CASE(OP_GT)
			CASE(OP_GTE)
			CASE(OP_EQ)
			CASE(OP_NEQ)
			CASE_OP(OP_JEZ)
			CASE_OP(OP_JMP)
			CASE_OP(OP_LIT)
			CASE_OP(OP_LOAD)
			CASE_OP(OP_STORE)
			CASE(OP_PRINT)
			CASE(OP_HALT)

			CASE(OP_RETURN)
			CASE_OP(OP_ALLOC)
			CASE_OP(OP_CLEAR)
			CASE_OP(OP_CALL)
			CASE_OP(OP_LOCAL)
			CASE_OP(OP_ARG)

		default:
			fatal("attempted to disassemble non-esistent opcode %d", *it);
			break;
		}
	}
	return output;
}

#undef CASE
#undef CASE_OP



void vm_exec(const int *code_buffer) {

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

	int32_t *code = code_buffer;
	int32_t *top = stack;
	for (;;) {
		int32_t op = *code++;
		switch (op) {
		//arithmetic
		case OP_ADD: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left + right);
			break;
		}
		case OP_SUB: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left - right);
			break;
		}
		case OP_MUL: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left * right);
			break;
		}
		case OP_DIV: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left / right);
			break;
		}
		case OP_NEG: {
			POPS(1);
			int32_t val = POP();
			PUSHES(1);
			PUSH(-val);
			break;
		}
		case OP_MOD: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left % right);
			break;
		}
		//bitwise
		case OP_BIT_AND: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left % right);
			break;
		}
		case OP_BIT_OR: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left | right);
			break;
		}
		case OP_BIT_NEG: {
			POPS(1);
			int32_t val = POP();
			PUSHES(1);
			PUSH(val);
			break;
		}
		case OP_BIT_XOR: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left ^ right);
			break;
		}
		//comparative
		case OP_LT: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left < right);
			break;
		}
		case OP_LTE: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left <= right);
			break;
		}
		case OP_GT: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left > right);
			break;
		}
		case OP_GTE: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left >= right);
			break;
		}
		case OP_EQ: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left == right);
			break;
		}
		case OP_NEQ: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left != right);
			break;
		}
		//boolean
		case OP_BOOL_AND: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left && right);
			break;
		}
		case OP_BOOL_OR: {
			POPS(2);
			int32_t right = POP();
			int32_t left = POP();
			PUSHES(1);
			PUSH(left || right);
			break;
		}
		case OP_BOOL_NOT: {
			POPS(1);
			int32_t val = POP();
			PUSHES(1);
			PUSH(!val);
			break;
		}		
		//flow control
		case OP_JEZ: {
			if (POP() == 0)
				code += *code;
			else
				code++;
			break;
		}
		case OP_JMP: {
			code += *code;
			break;
		}
		case OP_LIT: {
			PUSHES(1);
			PUSH(*code++);
			break;
		}
		case OP_LOAD: {
			PUSHES(1);
			PUSH(store[*code++]);
			break;
		}
		case OP_STORE: {
			POPS(1);
			store[*code++] = POP();
			break;
		}
		case OP_PRINT: {
			POPS(1);
			printf("%d\n", POP());
			break;
		}
		case OP_HALT: {
			return;
			break;
		}
		case OP_NOP: {
			//do nothing;
			break;
		}

		//function stuff
		case OP_RETURN: {
			POPS(1);
			code = POP() + code_buffer;
			break;
		}
		case OP_ALLOC: {
			assert(0);
			break;
		}
		case OP_CLEAR: {
			assert(0);
			break;
		}
		case OP_CALL: {
			PUSHES(1);
			PUSH(code - code_buffer + 1);		//return address
			code = *code + code_buffer;
			break;
		}
		case OP_LOCAL: {
			assert(0);
			break;
		}
		case OP_ARG: {
			assert(0);
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
	init_keywords_and_names();

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
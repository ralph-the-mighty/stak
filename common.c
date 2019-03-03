
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))



//stretchy buffers courtesy of Sean Barrett via Per Vognsen
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
#define buf_printf(b, ...) ((b) = buf__printf((b), __VA_ARGS__))
#define buf_clear(b) ((b) ? buf_len(b) = 0 : 0)

void *buf__grow(const void* buf, size_t new_len, size_t elem_size) {
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

char *buf__printf(char *buf, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	size_t cap = buf_cap(buf) - buf_len(buf);
	size_t n = 1 + vsnprintf(buf_end(buf), cap, fmt, args);
	va_end(args);
	if (n > cap) {
		buf__fit(buf, n + buf_len(buf));
		va_start(args, fmt);
		size_t new_cap = buf_cap(buf) - buf_len(buf);
		n = 1 + vsnprintf(buf_end(buf), new_cap, fmt, args);
		va_end(args);
	}
	buf__hdr(buf)->len += n - 1;
	return buf;
}







int load_file(const char *filename, char **result)
{
	int size = 0;
	FILE *f = fopen(filename, "rb");
	if (f == NULL) {
		*result = NULL;
		return -1; // -1 means file opening fail 
	}
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	*result = (char *)malloc(size + 1);
	if (size != fread(*result, sizeof(char), size, f)) {
		free(*result);
		return -2; // -2 means file reading fail 
	}
	fclose(f);
	(*result)[size] = 0;
	return size;
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
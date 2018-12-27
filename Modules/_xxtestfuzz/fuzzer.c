/* A fuzz test for CPython.

  The only exposed function is LLVMFuzzerTestOneInput, which is called by
  fuzzers and by the _fuzz module for smoke tests.

  To build exactly one fuzz test, as when running in oss-fuzz etc.,
  build with -D _Py_FUZZ_ONE and -D _Py_FUZZ_<test_name>. e.g. to build
  LLVMFuzzerTestOneInput to only run "fuzz_builtin_float", build this file with
      -D _Py_FUZZ_ONE -D _Py_FUZZ_fuzz_builtin_float.

  See the source code for LLVMFuzzerTestOneInput for details. */

#include <Python.h>
#include <stdlib.h>
#include <inttypes.h>

/*  Fuzz PyFloat_FromString as a proxy for float(str). */
static int fuzz_builtin_float(const char* data, size_t size) {
    PyObject* s = PyBytes_FromStringAndSize(data, size);
    if (s == NULL) return 0;
    PyObject* f = PyFloat_FromString(s);
    if (PyErr_Occurred() && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }

    Py_XDECREF(f);
    Py_DECREF(s);
    return 0;
}

#define MAX_INT_TEST_SIZE 0x10000

/* Fuzz PyLong_FromUnicodeObject as a proxy for int(str). */
static int fuzz_builtin_int(const char* data, size_t size) {
    /* Ignore test cases with very long ints to avoid timeouts
       int("9" * 1000000) is not a very interesting test caase */
    if (size > MAX_INT_TEST_SIZE) {
        return 0;
    }
    /* Pick a random valid base. (When the fuzzed function takes extra
       parameters, it's somewhat normal to hash the input to generate those
       parameters. We want to exercise all code paths, so we do so here.) */
    int base = _Py_HashBytes(data, size) % 37;
    if (base == 1) {
        // 1 is the only number between 0 and 36 that is not a valid base.
        base = 0;
    }
    if (base == -1) {
        return 0;  // An error occurred, bail early.
    }
    if (base < 0) {
        base = -base;
    }

    PyObject* s = PyUnicode_FromStringAndSize(data, size);
    if (s == NULL) {
        if (PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)) {
            PyErr_Clear();
        }
        return 0;
    }
    PyObject* l = PyLong_FromUnicodeObject(s, base);
    if (l == NULL && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }
    PyErr_Clear();
    Py_XDECREF(l);
    Py_DECREF(s);
    return 0;
}

static size_t strlen_with_max(const char *str, size_t max) {
    const char *start = str;
    while((str - start) < (long)max && *str) str++;
    return (size_t) (str - start);
}

/*
  Given a char buffer `data` of size `size`,
  returns a new one of length <= `size`, ending with a NULL character,
  but ensured to not contain any other NULL character.
  Its content is identitcal up to the first NULL character met in `data`.

  The returned pointer points to newly "malloc-ed" memory and hence must be "freed".
 */
static char* truncate_string_to_first_null_character(const char *data, size_t size) {
    const size_t newSize = strlen_with_max(data, size) + 1;
    char* nullTerminatedData = malloc(newSize);
    const size_t copiedSize = (newSize < size) ? newSize : size;
    strncpy(nullTerminatedData, data, copiedSize);
    nullTerminatedData[newSize - 1] = '\0';
    return nullTerminatedData;
}

static const char* _next_non_whitespace_char(const char* c) {
    while (*c != '\0' && (*c == ' ' || *c == '\n')) c++;
    return c;
}

static const char* _prev_non_whitespace_char(const char* data, int max_lookbehind) {
    const char* c = data;
    while ((data - c) < max_lookbehind) {
        c--;
        if (*c != ' ' && *c != '\n') break;
    };
    return c;
}

/* The fuzzing engine sometimes end up to generate huge integer computations that timeout.
   For exemple 52**52**52.
   Hence we have to blacklist those kind of inputs.
   Currently this only checks for: \d**\d{5} and \d**\d+**\d patterns */
static int is_python_input_at_risk_to_timeout(const char* data) {
    int i = -1;
    while (data[++i] != '\0') {
        // We start our investigation on every exponent operator: **
        if (data[i] != '*' || data[i + 1] != '*') {
            continue;
        }
        // We bail if the character before was not a digit
        const char* c = _prev_non_whitespace_char(data + i, i);
        if (*c < '0' || *c > '9') {
            continue;
        }
        // We now try to detect a too big exponent:
        int consecutive_digits_count = 0;
        c = _next_non_whitespace_char(data + i + 2) - 1;
        while (*++c != '\0') {
            if (*c < '0' || *c > '9') {
                const char* nc = _next_non_whitespace_char(c);
                if (consecutive_digits_count > 0 && *nc == '*' && nc[1] == '*') {
                    // We found a second exponent operator chained: we risk a timeout !
                    return 1;
                }
                // Neither a digit nor an exponent operator: we exit the sub-loop
                break;
            }
            consecutive_digits_count += 1;
            if (consecutive_digits_count >= 5) {
                // The exponent is at least 5 digits long: we risk a timeout !
                return 1;
            }
        }
    }
    return 0;
}

/* Fuzz PyRun_SimpleString */
static int fuzz_builtin_exec(const char* data, size_t size) {
    if (size <= 0) return 0;
    char* nullTerminatedData = truncate_string_to_first_null_character(data, size);
    if (!is_python_input_at_risk_to_timeout(nullTerminatedData)) {
        // We set Py_InspectFlag so that the next call returns normally even if a SystemExit is raised:
        Py_InspectFlag = 1;
        PyRun_SimpleString(nullTerminatedData);
        Py_InspectFlag = 0;
    }
    free(nullTerminatedData);
    return 0;
}

#ifndef JSON_DECODER_MODULE
#define JSON_DECODER_MODULE json.decoder
#endif
#define STR(s) #s
#define XSTR(x) STR(x)

// Fuzz json.decoder.JSONDecoder().decode(data)
// By making "json.decoder" a macro constant we allow reuse of this fuzz target
// for other implementations following the same API, e.g. simplejson
static int fuzz_json_decode(const char* data, size_t size) {
    if (size <= 0) return 0;
    char* nullTerminatedData = truncate_string_to_first_null_character(data, size);

    PyObject *args, *jsonDecoderModule, *JSONDecoderClass, *jsonDecoder, *decodeMethod;

    jsonDecoderModule = PyImport_ImportModule(XSTR(JSON_DECODER_MODULE));
    if (PyErr_Occurred()) {
        // An import error here is abnormal, we print the message:
        PyErr_Print();
        PyErr_Clear();
        return 0;
    }
    JSONDecoderClass = PyObject_GetAttrString(jsonDecoderModule, "JSONDecoder");
    Py_DECREF(jsonDecoderModule);

    args = Py_BuildValue("()");
    jsonDecoder = PyEval_CallObject(JSONDecoderClass, args);
    Py_DECREF(args);
    Py_DECREF(JSONDecoderClass);

    decodeMethod = PyObject_GetAttrString(jsonDecoder, "decode");
    Py_DECREF(jsonDecoder);

    args = Py_BuildValue("(s)", nullTerminatedData);
    if (PyErr_Occurred() != NULL) {
        PyErr_Clear();
    } else {
        PyEval_CallObject(decodeMethod, args);
        if (PyErr_Occurred() != NULL) {
            PyErr_Clear();
        }
        Py_DECREF(args);
    }
    Py_DECREF(decodeMethod);

    free(nullTerminatedData);
    return 0;
}

/* Fuzz PyUnicode_FromStringAndSize as a proxy for unicode(str). */
static int fuzz_builtin_unicode(const char* data, size_t size) {
    PyObject* s = PyUnicode_FromStringAndSize(data, size);
    if (s == NULL && PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)) {
        PyErr_Clear();
    }
    Py_XDECREF(s);
    return 0;
}

#define MAX_JSON_TEST_SIZE 0x10000

PyObject* json_loads_method = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_json_loads() {
    /* Import json.loads */
    PyObject* json_module = PyImport_ImportModule("json");
    if (json_module == NULL) {
        return 0;
    }
    json_loads_method = PyObject_GetAttrString(json_module, "loads");
    return json_loads_method != NULL;
}
/* Fuzz json.loads(x) */
static int fuzz_json_loads(const char* data, size_t size) {
    /* Since python supports arbitrarily large ints in JSON,
       long inputs can lead to timeouts on boring inputs like
       `json.loads("9" * 100000)` */
    if (size > MAX_JSON_TEST_SIZE) {
        return 0;
    }
    PyObject* input_bytes = PyBytes_FromStringAndSize(data, size);
    if (input_bytes == NULL) {
        return 0;
    }
    PyObject* parsed = _PyObject_CallOneArg(json_loads_method, input_bytes);
    if (parsed == NULL) {
        /* Ignore ValueError as the fuzzer will more than likely
           generate some invalid json and values */
        if (PyErr_ExceptionMatches(PyExc_ValueError) ||
        /* Ignore RecursionError as the fuzzer generates long sequences of
           arrays such as `[[[...` */
            PyErr_ExceptionMatches(PyExc_RecursionError) ||
        /* Ignore unicode errors, invalid byte sequences are common */
            PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)
        ) {
            PyErr_Clear();
        }
    }
    Py_DECREF(input_bytes);
    Py_XDECREF(parsed);
    return 0;
}

#define MAX_RE_TEST_SIZE 0x10000

PyObject* sre_compile_method = NULL;
PyObject* sre_error_exception = NULL;
int SRE_FLAG_DEBUG = 0;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_sre_compile() {
    /* Import sre_compile.compile and sre.error */
    PyObject* sre_compile_module = PyImport_ImportModule("sre_compile");
    if (sre_compile_module == NULL) {
        return 0;
    }
    sre_compile_method = PyObject_GetAttrString(sre_compile_module, "compile");
    if (sre_compile_method == NULL) {
        return 0;
    }

    PyObject* sre_constants = PyImport_ImportModule("sre_constants");
    if (sre_constants == NULL) {
        return 0;
    }
    sre_error_exception = PyObject_GetAttrString(sre_constants, "error");
    if (sre_error_exception == NULL) {
        return 0;
    }
    PyObject* debug_flag = PyObject_GetAttrString(sre_constants, "SRE_FLAG_DEBUG");
    if (debug_flag == NULL) {
        return 0;
    }
    SRE_FLAG_DEBUG = PyLong_AsLong(debug_flag);
    return 1;
}
/* Fuzz _sre.compile(x) */
static int fuzz_sre_compile(const char* data, size_t size) {
    /* Ignore really long regex patterns that will timeout the fuzzer */
    if (size > MAX_RE_TEST_SIZE) {
        return 0;
    }
    /* We treat the first 2 bytes of the input as a number for the flags */
    if (size < 2) {
        return 0;
    }
    uint16_t flags = ((uint16_t*) data)[0];
    /* We remove the SRE_FLAG_DEBUG if present. This is because it
       prints to stdout which greatly decreases fuzzing speed */
    flags &= ~SRE_FLAG_DEBUG;

    /* Pull the pattern from the remaining bytes */
    PyObject* pattern_bytes = PyBytes_FromStringAndSize(data + 2, size - 2);
    if (pattern_bytes == NULL) {
        return 0;
    }
    PyObject* flags_obj = PyLong_FromUnsignedLong(flags);
    if (flags_obj == NULL) {
        Py_DECREF(pattern_bytes);
        return 0;
    }

    /* compiled = _sre.compile(data[2:], data[0:2] */
    PyObject* compiled = PyObject_CallFunctionObjArgs(
        sre_compile_method, pattern_bytes, flags_obj, NULL);
    /* Ignore ValueError as the fuzzer will more than likely
       generate some invalid combination of flags */
    if (compiled == NULL && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }
    /* Ignore some common errors thrown by sre_parse:
       Overflow, Assertion and Index */
    if (compiled == NULL && (PyErr_ExceptionMatches(PyExc_OverflowError) ||
                             PyErr_ExceptionMatches(PyExc_AssertionError) ||
                             PyErr_ExceptionMatches(PyExc_IndexError))
    ) {
        PyErr_Clear();
    }
    /* Ignore re.error */
    if (compiled == NULL && PyErr_ExceptionMatches(sre_error_exception)) {
        PyErr_Clear();
    }

    Py_DECREF(pattern_bytes);
    Py_DECREF(flags_obj);
    Py_XDECREF(compiled);
    return 0;
}

/* Some random patterns used to test re.match.
   Be careful not to add catostraphically slow regexes here, we want to
   exercise the matching code without causing timeouts.*/
static const char* regex_patterns[] = {
    ".", "^", "abc", "abc|def", "^xxx$", "\\b", "()", "[a-zA-Z0-9]",
    "abc+", "[^A-Z]", "[x]", "(?=)", "a{z}", "a+b", "a*?", "a??", "a+?",
    "{}", "a{,}", "{", "}", "^\\(*\\d{3}\\)*( |-)*\\d{3}( |-)*\\d{4}$",
    "(?:a*)*", "a{1,2}?"
};
const size_t NUM_PATTERNS = sizeof(regex_patterns) / sizeof(regex_patterns[0]);
PyObject** compiled_patterns = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_sre_match() {
    PyObject* re_module = PyImport_ImportModule("re");
    if (re_module == NULL) {
        return 0;
    }
    compiled_patterns = (PyObject**) PyMem_RawMalloc(
        sizeof(PyObject*) * NUM_PATTERNS);
    if (compiled_patterns == NULL) {
        PyErr_NoMemory();
        return 0;
    }

    /* Precompile all the regex patterns on the first run for faster fuzzing */
    for (size_t i = 0; i < NUM_PATTERNS; i++) {
        PyObject* compiled = PyObject_CallMethod(
            re_module, "compile", "y", regex_patterns[i]);
        /* Bail if any of the patterns fail to compile */
        if (compiled == NULL) {
            return 0;
        }
        compiled_patterns[i] = compiled;
    }
    return 1;
}
/* Fuzz re.match(x) */
static int fuzz_sre_match(const char* data, size_t size) {
    if (size < 1 || size > MAX_RE_TEST_SIZE) {
        return 0;
    }
    /* Use the first byte as a uint8_t specifying the index of the
       regex to use */
    unsigned char idx = (unsigned char) data[0];
    idx = idx % NUM_PATTERNS;

    /* Pull the string to match from the remaining bytes */
    PyObject* to_match = PyBytes_FromStringAndSize(data + 1, size - 1);
    if (to_match == NULL) {
        return 0;
    }

    PyObject* pattern = compiled_patterns[idx];
    PyObject* match_callable = PyObject_GetAttrString(pattern, "match");

    PyObject* matches = _PyObject_CallOneArg(match_callable, to_match);

    Py_XDECREF(matches);
    Py_DECREF(match_callable);
    Py_DECREF(to_match);
    return 0;
}

#define MAX_CSV_TEST_SIZE 0x10000
PyObject* csv_module = NULL;
PyObject* csv_error = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_csv_reader() {
    /* Import csv and csv.Error */
    csv_module = PyImport_ImportModule("csv");
    if (csv_module == NULL) {
        return 0;
    }
    csv_error = PyObject_GetAttrString(csv_module, "Error");
    return csv_error != NULL;
}
/* Fuzz csv.reader([x]) */
static int fuzz_csv_reader(const char* data, size_t size) {
    if (size < 1 || size > MAX_CSV_TEST_SIZE) {
        return 0;
    }
    /* Ignore non null-terminated strings since _csv can't handle
       embeded nulls */
    if (memchr(data, '\0', size) == NULL) {
        return 0;
    }

    PyObject* s = PyUnicode_FromString(data);
    /* Ignore exceptions until we have a valid string */
    if (s == NULL) {
        PyErr_Clear();
        return 0;
    }

    /* Split on \n so we can test multiple lines */
    PyObject* lines = PyObject_CallMethod(s, "split", "s", "\n");
    if (lines == NULL) {
        Py_DECREF(s);
        return 0;
    }

    PyObject* reader = PyObject_CallMethod(csv_module, "reader", "N", lines);
    if (reader) {
        /* Consume all of the reader as an iterator */
        PyObject* parsed_line;
        while ((parsed_line = PyIter_Next(reader))) {
            Py_DECREF(parsed_line);
        }
    }

    /* Ignore csv.Error because we're probably going to generate
       some bad files (embeded new-lines, unterminated quotes etc) */
    if (PyErr_ExceptionMatches(csv_error)) {
        PyErr_Clear();
    }

    Py_XDECREF(reader);
    Py_DECREF(s);
    return 0;
}

/* Run fuzzer and abort on failure. */
static int _run_fuzz(const uint8_t *data, size_t size, int(*fuzzer)(const char* , size_t)) {
    int rv = fuzzer((const char*) data, size);
    if (PyErr_Occurred()) {
        /* Fuzz tests should handle expected errors for themselves.
           This is last-ditch check in case they didn't. */
        PyErr_Print();
        abort();
    }
    /* Someday the return value might mean something, propagate it. */
    return rv;
}

/* CPython generates a lot of leak warnings for whatever reason. */
int __lsan_is_turned_off(void) { return 1; }


int LLVMFuzzerInitialize(int *argc, char ***argv) {
    wchar_t* wide_program_name = Py_DecodeLocale(*argv[0], NULL);
    Py_SetProgramName(wide_program_name);
    return 0;
}

/* Fuzz test interface.
   This returns the bitwise or of all fuzz test's return values.

   All fuzz tests must return 0, as all nonzero return codes are reserved for
   future use -- we propagate the return values for that future case.
   (And we bitwise or when running multiple tests to verify that normally we
   only return 0.) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!Py_IsInitialized()) {
        /* LLVMFuzzerTestOneInput is called repeatedly from the same process,
           with no separate initialization phase, sadly, so we need to
           initialize CPython ourselves on the first run. */
        Py_InitializeEx(0);
    }

    int rv = 0;

#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_float)
    rv |= _run_fuzz(data, size, fuzz_builtin_float);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_int)
    rv |= _run_fuzz(data, size, fuzz_builtin_int);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_unicode)
    rv |= _run_fuzz(data, size, fuzz_builtin_unicode);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_exec)
    assert(is_python_input_at_risk_to_timeout("999 **  99999"));
    assert(is_python_input_at_risk_to_timeout("52**52**52"));
    assert(!is_python_input_at_risk_to_timeout("2**10"));
    assert(!is_python_input_at_risk_to_timeout("**10"));
    rv |= _run_fuzz(data, size, fuzz_builtin_exec);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_json_decode)
    rv |= _run_fuzz(data, size, fuzz_json_decode);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_json_loads)
    static int JSON_LOADS_INITIALIZED = 0;
    if (!JSON_LOADS_INITIALIZED && !init_json_loads()) {
        PyErr_Print();
        abort();
    } else {
        JSON_LOADS_INITIALIZED = 1;
    }

    rv |= _run_fuzz(data, size, fuzz_json_loads);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_sre_compile)
    static int SRE_COMPILE_INITIALIZED = 0;
    if (!SRE_COMPILE_INITIALIZED && !init_sre_compile()) {
        PyErr_Print();
        abort();
    } else {
        SRE_COMPILE_INITIALIZED = 1;
    }

    rv |= _run_fuzz(data, size, fuzz_sre_compile);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_sre_match)
    static int SRE_MATCH_INITIALIZED = 0;
    if (!SRE_MATCH_INITIALIZED && !init_sre_match()) {
        PyErr_Print();
        abort();
    } else {
        SRE_MATCH_INITIALIZED = 1;
    }

    rv |= _run_fuzz(data, size, fuzz_sre_match);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_csv_reader)
    static int CSV_READER_INITIALIZED = 0;
    if (!CSV_READER_INITIALIZED && !init_csv_reader()) {
        PyErr_Print();
        abort();
    } else {
        CSV_READER_INITIALIZED = 1;
    }

    rv |= _run_fuzz(data, size, fuzz_csv_reader);
#endif
  return rv;
}

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
    body {
      color: #FEFEFE;
      background-color: #0A0B11;
      margin: 0 auto;
      padding: 1em 0 1em 0;
    }
    a { 
      color: #93ffd7;
      text-decoration: none; 
    }
    @font-face { 
      font-family: "unifont"; 
      src: url("./unifont.woff") format('woff'); 
    }
    pre { 
      font-family: "unifont", "Lucida Console", monospace, Monaco; 
      font-size:16px; 
      line-height: 1.0;
      padding-left: 20px;
    }
    .txtdiv {
      display: block;
      text-align: left;
    }
    </style>
    <title>jc3wrld999</title>
</head>
<body>
할당자를 사용자 정의 구현으로 바꾸는 방법론 중에서 __malloc_hook 에 대한 것을 간략히 개요로 설명합니다.
자세한 것은 man page 에서 'man __malloc_hook' 확인하시면 어렵지 않게 이해는 되며 이런게 있다는 소개입니다.
주로 다음과 같은 경우 이를 활용할 수 있다고 생각됩니다.

완전히 새로운 알고리즘의 할당자 구현으로 성능 및 메모리 사용 효율을 증대하고자 하는 경우

새로운 할당자를 만들려고 할 때 (jemalloc 같은 구현)
보통 기존 할당자는 성능을 중점으로 brk 를 좀더 낭비하여 적절한 요구할당 크기를 빠르게 찾는데 중점을 두는거 같습니다.


기존 할당자에서 고질적인 메모리 누수를 감지하고 이를 방어하는 구현을 요구하는 경우

메모리 누수를 추적카운팅하고자 할 때 사용할 수 있습니다.
참고) strongswan의 leak_detective 구현을 참고하시면 많은 정보를 얻을 수 있습니다. (정말로 잘 만들어진 leak 감지 구현입니다.)


/*

=> 여기 명시되는 구현은 의사구현으로 개념적인 설명에 대한 소스입니다. 컴파일은 안되요.
=> hooking 기법은 크게 2가지가 있습니다. glibc 차원에서 제공하는 전역 훅 포인터를 교체하도록 인터페스가 마련되있는 방법에 접근하는 것과 LD_PRELOAD 라는 런타임에서 심볼을 override 하는 기법이 있습니다.

* libc 는 여러 종류가 있습니다. glibc 기준으로는 내부 정의된 다음과 같은 전역 함수 포인터를 내 구현 함수로 교체하면 hooking 이 됩니다.
   반드시 모든 library 보다 앞서서 대입이 일어나야 합니다. 때문에 단순히 main 함수에서 하시면 안되고 constructor 함수정의에서 구현해야 합니다.
   
        __malloc_hook = hwport_leak_detective_malloc_hook;  // 할당 함수
        __realloc_hook = hwport_leak_detective_realloc_hook; // 재할당 함수
        __memalign_hook = hwport_leak_detective_memalign_hook; // 정렬 할당 함수
        __free_hook = hwport_leak_detective_free_hook; // 해제 함수
        __after_morecore_hook = hwport_leak_detective_after_morecore_hook; // brk 증식 구현 함수
        
    main 함수 및 모든 library 초기화 이전에 수행되기 위해서 __attribute__((constructor)) 속성을 가진 함수에서 최고 우선순위로 지정되어 실행되도록 해야 합니다.        
    위 함수포인터에 내 구현 함수를 대입하기 전에 기존 포인터가 저장한 값을 백업해두는 구현이 반드시 필요합니다. (완전히 할당자를 새롭게 구현하는 것이 아닌 경우에 필요)
    
    malloc 내부 자료구조와 호환된다면 일부 함수만 교체하면 되지만 그렇지 않은 경우는 위 모든 함수를 교체해야 합니다.
    
    brk 란? 'man brk' 하시면 대략적인 설명을 보실 수 있고 실제 SHR/RSS 메모리에 해당하는 HEAP의 end point 를 늘리는 것을 의미합니다.
    
    memalign 란? 메모리 정렬을 고려한 할당자이며 mmap 등에 mapping 할 할당자의 경우 대부분 이 할당자로 사용해야 합니다.
    
대략 다음의 원형에 맞도록 함수를 구현하시면 됩니다.
void *hwport_leak_detective_malloc_hook(size_t s_size, const void *s_caller)
void *hwport_leak_detective_realloc_hook(void *s_old_i_ptr, size_t s_size, const void *s_caller)
void *hwport_leak_detective_memalign_hook(size_t s_alignment_size, size_t s_size, const void *s_caller)
void hwport_leak_detective_free_hook(void *s_new_i_ptr, const void *s_caller)
void hwport_leak_detective_after_morecore_hook(void)

*/


/* ----------------------------- 아래 내용은 .so 로 빌드 후 LD_PRELOAD 로 hooking 할 수 있는 구현 예시입니다. ------------ */


/*
    Copyright (C) HWPORT.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_hwport_leak_detective_source_hwport_leak_detective_c__)
# define __def_hwport_leak_detective_source_hwport_leak_detective_c__ "hwport-leak-detective.c"

/* ---- */

#if !defined(_ISOC99_SOURCE)
# define _ISOC99_SOURCE 1L
#endif

#if !defined(_GNU_SOURCE)
# define _GNU_SOURCE 1L
#endif

#include <sys/types.h>

#include <inttypes.h>

#include <malloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dlfcn.h>
#include <execinfo.h>

/* ---- */

#define def_hwport_leak_detective_debug_call_hook 0L

/* ---- */

#define hwport_likely(m_expression) __builtin_expect(!!(long)(m_expression),1L)
#define hwport_unlikely(m_expression) __builtin_expect(!!(long)(m_expression),0L)

#if __GLIBC_PREREQ(2,4)
# define def_hwport_leak_detective_thread_local_storage __thread
#endif

#if 0L
# define def_hwport_leak_detective_default_alignment_size ((size_t)8u)
#else
# define def_hwport_leak_detective_default_alignment_size sizeof(unsigned int)
#endif

#define __hwport_alignment_size(_m_value,_m_alignment_size) (((_m_value)==0)?0:(((((_m_value)-1)/(_m_alignment_size))*(_m_alignment_size))+(_m_alignment_size)))

#define hwport_peek_const_vector(m_cast,m_base,m_sign,m_offset) ((m_cast)((const void *)(((const uint8_t *)(m_base)) m_sign ((size_t)(m_offset)))))
#define hwport_peek_const_f(m_cast,m_base,m_offset) hwport_peek_const_vector(m_cast,m_base,+,m_offset)
#define hwport_peek_const_r(m_cast,m_base,m_offset) hwport_peek_const_vector(m_cast,m_base,-,m_offset)
#define hwport_peek_const(m_base,m_offset) hwport_peek_const_vector(const void *,m_base,+,m_offset)

#define hwport_peek_vector(m_cast,m_base,m_sign,m_offset) ((m_cast)((void *)(((uint8_t *)(m_base)) m_sign ((size_t)(m_offset)))))
#define hwport_peek_f(m_cast,m_base,m_offset) hwport_peek_vector(m_cast,m_base,+,m_offset)
#define hwport_peek_r(m_cast,m_base,m_offset) hwport_peek_vector(m_cast,m_base,-,m_offset)
#define hwport_peek(m_base,m_offset) hwport_peek_vector(void *,m_base,+,m_offset)

#define hwport_peek_const_type(m_cast,m_from,m_offset) (*(hwport_peek_const_f(const m_cast *,m_from,m_offset)))
#define hwport_peek_uint8(m_from,m_offset) hwport_peek_const_type(uint8_t,m_from,m_offset)
#define hwport_peek_uint16(m_from,m_offset) hwport_peek_const_type(uint16_t,m_from,m_offset)
#define hwport_peek_uint32(m_from,m_offset) hwport_peek_const_type(uint32_t,m_from,m_offset)
#define hwport_peek_uint64(m_from,m_offset) hwport_peek_const_type(uint64_t,m_from,m_offset)

#define hwport_peek_type(m_cast,m_from,m_offset) (*(hwport_peek_f(m_cast *,m_from,m_offset)))
#define hwport_poke_type(m_cast,m_to,m_offset,m_value) do{hwport_peek_type(m_cast,m_to,m_offset)=(m_cast)(m_value);}while(0)
#define hwport_poke_uint8(m_to,m_offset,m_value) hwport_poke_type(uint8_t,m_to,m_offset,m_value)
#define hwport_poke_uint16(m_to,m_offset,m_value) hwport_poke_type(uint16_t,m_to,m_offset,m_value)
#define hwport_poke_uint32(m_to,m_offset,m_value) hwport_poke_type(uint32_t,m_to,m_offset,m_value)
#define hwport_poke_uint64(m_to,m_offset,m_value) hwport_poke_type(uint64_t,m_to,m_offset,m_value)

typedef void (* volatile __hwport_leak_detective_malloc_initialize_t)(void);
#define hwport_leak_detective_malloc_initialize_t __hwport_leak_detective_malloc_initialize_t

typedef void *(* volatile __hwport_leak_detective_malloc_t)(size_t, const void *);
#define hwport_leak_detective_malloc_t __hwport_leak_detective_malloc_t

typedef void *(* volatile __hwport_leak_detective_realloc_t)(void *, size_t, const void *);
#define hwport_leak_detective_realloc_t __hwport_leak_detective_realloc_t

typedef void *(* volatile __hwport_leak_detective_memalign_t)(size_t, size_t, const void *);
#define hwport_leak_detective_memalign_t __hwport_leak_detective_memalign_t

typedef void (* volatile __hwport_leak_detective_free_t)(void *, const void *);
#define hwport_leak_detective_free_t __hwport_leak_detective_free_t

typedef void (* volatile __hwport_leak_detective_after_morecore_t)(void);
#define hwport_leak_detective_after_morecore_t __hwport_leak_detective_after_morecore_t

#define def_hwport_leak_detective_magic_code ((uint32_t)0xa55a55aau)
typedef struct hwport_leak_detective_header_ts __hwport_leak_detective_header_t;
#define hwport_leak_detective_header_t __hwport_leak_detective_header_t
typedef struct hwport_leak_detective_trailer_ts __hwport_leak_detective_trailer_t;
#define hwport_leak_detective_trailer_t __hwport_leak_detective_trailer_t
struct hwport_leak_detective_header_ts {
        hwport_leak_detective_header_t *m_prev;
        hwport_leak_detective_header_t *m_next;
        hwport_leak_detective_trailer_t *m_trailer;

        size_t m_size;

        void **m_backtrace;

#if defined(def_hwport_leak_detective_magic_code)
        uint32_t m_magic_code;
#endif
};
struct hwport_leak_detective_trailer_ts {
        hwport_leak_detective_header_t *m_this;
#if defined(def_hwport_leak_detective_magic_code)
        uint32_t m_magic_code;
#endif
};

typedef struct hwport_leak_detective_hook_ts __hwport_leak_detective_hook_t;
#define hwport_leak_detective_hook_t __hwport_leak_detective_hook_t
struct hwport_leak_detective_hook_ts {
        volatile int m_reference_count;

        size_t m_header_size;
        size_t m_trailer_size;

        hwport_leak_detective_malloc_initialize_t m_malloc_initialize;

        hwport_leak_detective_malloc_t m_malloc;
        hwport_leak_detective_realloc_t m_realloc;
        hwport_leak_detective_memalign_t m_memalign;
        hwport_leak_detective_free_t m_free;
        hwport_leak_detective_after_morecore_t m_after_morecore;

        volatile int m_count;
        volatile int m_size;

        hwport_leak_detective_header_t *m_head;
        hwport_leak_detective_header_t *m_tail;
};

/* ---- */

static size_t __hwport_dump_space_buffer(char *s_buffer, size_t s_buffer_size, int s_depth);
static size_t __hwport_dump_buffer(char *s_buffer, size_t s_buffer_size, int s_depth, const void *s_data, size_t s_size);
static size_t __hwport_dump(int s_depth, const void *s_data, size_t s_size);

static int __hwport_leak_detective_update_statistics(int s_count, int s_size);
static const char *__hwport_basename_c(const char *s_pathname);
static const char *__hwport_leak_detective_get_symbol(const void *s_caller, const char **s_caller_symbol_name, const char **s_caller_filename);

static size_t __hwport_leak_detective_pre_alloc_handler(size_t s_size, const void *s_caller);
static void *__hwport_leak_detective_post_alloc_handler(void *s_new_o_ptr, size_t s_size, size_t s_modified_size, const void *s_caller);
static void *__hwport_leak_detective_pre_free_handler(void *s_new_i_ptr, const void *s_caller);
static void __hwport_leak_detective_post_free_handler(void *s_new_o_ptr, const void *s_caller);

static void *hwport_leak_detective_malloc_hook(size_t s_size, const void *s_caller);
static void *hwport_leak_detective_realloc_hook(void *s_old_i_ptr, size_t s_size, const void *s_caller);
static void *hwport_leak_detective_memalign_hook(size_t s_alignment_size, size_t s_size, const void *s_caller);
static void hwport_leak_detective_free_hook(void *s_new_i_ptr, const void *s_caller);
static void hwport_leak_detective_after_morecore_hook(void);

static void hwport_leak_detective_save_hook(void);
static void hwport_leak_detective_restore_hook(void);
static void hwport_leak_detective_set_hook(void);

#if 0L
static void hwport_leak_detective_malloc_initialize_hook(void);
#endif
static void hwport_leak_detective_malloc_deinitialize_hook(void);

void hwport_leak_detective_report(void);

void __attribute__((constructor)) hwport_leak_detective_init(void);
void __attribute__((destructor)) hwport_leak_detective_deinit(void);

/* ---- */

static hwport_leak_detective_hook_t g_hwport_leak_detective_info = {
        .m_reference_count = 0,

        .m_header_size = __hwport_alignment_size(sizeof(hwport_leak_detective_header_t), def_hwport_leak_detective_default_alignment_size),
        .m_trailer_size = __hwport_alignment_size(sizeof(hwport_leak_detective_trailer_t), def_hwport_leak_detective_default_alignment_size),

        .m_malloc_initialize = (hwport_leak_detective_malloc_initialize_t)0,

        .m_malloc = (hwport_leak_detective_malloc_t)0,
        .m_realloc = (hwport_leak_detective_realloc_t)0,
        .m_memalign = (hwport_leak_detective_memalign_t)0,
        .m_free = (hwport_leak_detective_free_t)0,
        .m_after_morecore = (hwport_leak_detective_after_morecore_t)0,

        .m_count = 0,
        .m_size = 0,

        .m_head = (hwport_leak_detective_header_t *)0,
        .m_tail = (hwport_leak_detective_header_t *)0,
};

/* ---- */

static size_t __hwport_dump_space_buffer(char *s_buffer, size_t s_buffer_size, int s_depth)
{
    size_t s_offset;
    int s_count;

        if(s_buffer == ((char *)0)) {
        s_offset = (size_t)0u;
            for(s_count = 0;s_count < s_depth;s_count++) {
                s_offset += (size_t)fprintf(
                                stderr,
                    "  "
                );
            }

                return(s_offset);
        }

    s_offset = (size_t)0u;
    for(s_count = 0;s_count < s_depth;s_count++) {
        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "  "
        );
    }

    return(s_offset);
}

static size_t __hwport_dump_buffer(char *s_buffer, size_t s_buffer_size, int s_depth, const void *s_data, size_t s_size)
{
    size_t s_offset;

    size_t s_o;
    size_t s_w;
    size_t s_i;
    uint8_t s_b[17];

    s_offset = (size_t)0u;

    s_b[16] = (uint8_t)'\0';
    s_o = (size_t)0u;

        if(s_buffer == ((char *)0)) {
                while(s_o < s_size) {
                        s_w = ((s_size - s_o) < ((size_t)16u)) ? (s_size - s_o) : ((size_t)16u);

                        s_offset += __hwport_dump_space_buffer(
                                (char *)0,
                                s_buffer_size - s_offset,
                                s_depth
                        );

                        s_offset += (size_t)fprintf(
                                stderr,
                                "%08lX",
                                (unsigned long)s_o
                        );

                        for(s_i = (size_t)0u;s_i < s_w;s_i++){
                                if(s_i == ((size_t)8u)) {
                                        s_offset += (size_t)fprintf(
                                                stderr,
                                                " | "
                                        );
                                }
                                else {
                                        s_offset += (size_t)fprintf(
                                                stderr,
                                                " "
                                        );
                                }

                                s_b[s_i] = *(((const uint8_t *)s_data) + s_o + s_i);

                                s_offset += (size_t)fprintf(
                                        stderr,
                                        "%02X",
                                        (unsigned int)s_b[s_i]
                                );

                                if((s_b[s_i] & 0x80) || (s_b[s_i] < ' ')) {
                                        s_b[s_i] = '.';
                                }
                        }

                        while(s_i < 16) {
                                if(s_i == 8) {
                                        s_offset += (size_t)fprintf(
                                                stderr,
                                                "     "
                                        );
                                }
                                else {
                                        s_offset += (size_t)fprintf(
                                                stderr,
                                                "   "
                                        );
                                }

                                s_b[s_i] = ' ';
                                ++s_i;
                        }

                        s_offset += (size_t)fprintf(
                                stderr,
                                " [%s]\n",
                                (char *)(&s_b[0])
                        );

                        s_o += (size_t)16u;
                }

                return(s_offset);
        }

    while(s_o < s_size) {
        s_w = ((s_size - s_o) < ((size_t)16u)) ? (s_size - s_o) : ((size_t)16u);

        s_offset += __hwport_dump_space_buffer(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            s_depth
        );

        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            "%08lX",
            (unsigned long)s_o
        );

        for(s_i = (size_t)0u;s_i < s_w;s_i++){
            if(s_i == ((size_t)8u)) {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    " | "
                );
            }
            else {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    " "
                );
            }

            s_b[s_i] = *(((const uint8_t *)s_data) + s_o + s_i);

            s_offset += (size_t)snprintf(
                (char *)(&s_buffer[s_offset]),
                s_buffer_size - s_offset,
                "%02X",
                (unsigned int)s_b[s_i]
            );

            if((s_b[s_i] & 0x80) || (s_b[s_i] < ' ')) {
                s_b[s_i] = '.';
            }
        }

        while(s_i < 16) {
            if(s_i == 8) {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    "     "
                );
            }
            else {
                s_offset += (size_t)snprintf(
                    (char *)(&s_buffer[s_offset]),
                    s_buffer_size - s_offset,
                    "   "
                );
            }

            s_b[s_i] = ' ';
            ++s_i;
        }

        s_offset += (size_t)snprintf(
            (char *)(&s_buffer[s_offset]),
            s_buffer_size - s_offset,
            " [%s]\n",
            (char *)(&s_b[0])
        );

        s_o += (size_t)16u;
    }

    return(s_offset);
}

static size_t __hwport_dump(int s_depth, const void *s_data, size_t s_size)
{
        return(__hwport_dump_buffer((char *)0, (size_t)0, s_depth, s_data, s_size));
}

static int __hwport_leak_detective_update_statistics(int s_count, int s_size)
{
        int s_result;

        s_result = __sync_add_and_fetch(&g_hwport_leak_detective_info.m_count, s_count);
        (void)__sync_add_and_fetch(&g_hwport_leak_detective_info.m_size, s_size);

        return(s_result);
}

static const char *__hwport_basename_c(const char *s_pathname)
{
    static const char sg_dot_string[] = {"."};

    size_t s_count;
    size_t s_offset;

    if(hwport_unlikely(s_pathname == ((const char *)0))) {
        return((const char *)(&sg_dot_string[0]));
    }

    if(hwport_unlikely(s_pathname[0] == ((char)0))) {
        return(s_pathname);
    }

    s_count = (size_t)0u;
    s_offset = strlen(s_pathname);
    while(s_offset > ((size_t)0u)) {
        if((s_pathname[s_offset - ((size_t)1u)] == ((unsigned char)'/')) ||
           (s_pathname[s_offset - ((size_t)1u)] == ((unsigned char)'\\'))) {
            if(s_count > ((size_t)0u)) {
                break;
            }
        }
        else {
            ++s_count;
        }
        --s_offset;
    }

    s_pathname = (const char *)(&s_pathname[s_offset]);
    if(hwport_unlikely(strlen(s_pathname) <= ((size_t)0u))) {
        return((const char *)(&sg_dot_string[0]));
    }

    return(s_pathname);
}

static const char *__hwport_leak_detective_get_symbol(const void *s_caller, const char **s_caller_symbol_name, const char **s_caller_filename)
{
#if defined(def_hwport_leak_detective_thread_local_storage)
        static def_hwport_leak_detective_thread_local_storage char sg_default_symbol[ 512 ];
#else
# warning not supported thread local storage !
        static char sg_default_symbol[ 512 ];
#endif

        Dl_info s_info;

        if(hwport_unlikely(dladdr(s_caller, (Dl_info *)(&s_info)) == 0)) {
                if(s_caller_symbol_name != ((const char **)0)) {
                        *s_caller_symbol_name = (const char *)0;
                }
                if(s_caller_filename != ((const char **)0)) {
                        *s_caller_filename = (const char *)0;
                }

                (void)snprintf(
                        (char *)(&sg_default_symbol),
                        sizeof(sg_default_symbol),
                        "%p(unresolved)",
                        s_caller
                );

                return((const char *)(&sg_default_symbol[0]));
        }

        if(s_caller_symbol_name != ((const char **)0)) {
                *s_caller_symbol_name = s_info.dli_sname;
        }
        if(s_caller_filename != ((const char **)0)) {
                *s_caller_filename = s_info.dli_fname;
        }

        if(hwport_unlikely(s_info.dli_sname == ((const char *)0))) {
                (void)snprintf(
                        (char *)(&sg_default_symbol),
                        sizeof(sg_default_symbol),
                        "%p(%s)",
                        s_caller,
                        (s_info.dli_fname == ((const char *)0)) ? "unknown" : __hwport_basename_c(s_info.dli_fname)
                );

                return((const char *)(&sg_default_symbol[0]));
        }

        (void)snprintf(
                (char *)(&sg_default_symbol),
                sizeof(sg_default_symbol),
                "%s(%s)",
                s_info.dli_sname,
                (s_info.dli_fname == ((const char *)0)) ? "unknown" : __hwport_basename_c(s_info.dli_fname)
        );

        return((const char *)(&sg_default_symbol[0]));
}

static size_t __hwport_leak_detective_pre_alloc_handler(size_t s_size, const void *s_caller)
{
        size_t s_modified_size;

        (void)s_caller;

        s_modified_size = (size_t)0u;
        s_modified_size += g_hwport_leak_detective_info.m_header_size;
        s_modified_size += __hwport_alignment_size(s_size, def_hwport_leak_detective_default_alignment_size);
        s_modified_size += g_hwport_leak_detective_info.m_trailer_size;

        return(s_modified_size);
}

static void *__hwport_leak_detective_post_alloc_handler(void *s_new_o_ptr, size_t s_size, size_t s_modified_size, const void *s_caller)
{
        hwport_leak_detective_header_t *s_header;

        void *s_new_i_ptr;

#if defined(def_hwport_leak_detective_thread_local_storage) /* for minimal stack frame */
        static def_hwport_leak_detective_thread_local_storage void *s_backtrace[ 128 ];
#else
        void *s_backtrace[ 48 ];
#endif
        int s_backtrace_count;
        int s_backtrace_index;

        if(s_new_o_ptr == ((void *)0)) {
                return((void *)0);
        }

        s_header = hwport_peek_f(hwport_leak_detective_header_t *,s_new_o_ptr,0);
        s_new_i_ptr = hwport_peek(s_new_o_ptr,g_hwport_leak_detective_info.m_header_size);

        s_header->m_prev = (hwport_leak_detective_header_t *)0;
        s_header->m_next = (hwport_leak_detective_header_t *)0;
        s_header->m_trailer = hwport_peek_f(hwport_leak_detective_trailer_t *,s_new_o_ptr,s_modified_size - g_hwport_leak_detective_info.m_trailer_size);

        s_header->m_size = s_size;

    s_backtrace_count = backtrace(
            (void **)(&s_backtrace[0]),
                (int)(sizeof(s_backtrace) / sizeof(void *))
        );
        if(hwport_unlikely(s_backtrace_count <= 0)) {
                union {
                        const void *m_const_ptr;
                        void *m_ptr;
                }s_union_ptr;

                s_backtrace_count = 1;

                s_backtrace_index = 0;
                s_union_ptr.m_const_ptr = s_caller;
                s_backtrace[s_backtrace_index] = s_union_ptr.m_ptr;
        }
        else {
                for(s_backtrace_index = 0;s_backtrace_index < s_backtrace_count;s_backtrace_index++) {
                        if(s_backtrace[s_backtrace_index] == s_caller) {
                                break;
                        }
                }
                if(hwport_unlikely(s_backtrace_index >= s_backtrace_count)) { /* not found caller */
                        s_backtrace_index = 0;
                }
        }
        s_header->m_backtrace = (void **)malloc(sizeof(void *) * ((size_t)((s_backtrace_count - s_backtrace_index) + 1)));
        if(s_header->m_backtrace != ((void **)0)) {
                (void)memcpy((void *)s_header->m_backtrace, (void *)(&s_backtrace[s_backtrace_index]), sizeof(void *) * ((size_t)(s_backtrace_count - s_backtrace_index)));
                s_header->m_backtrace[s_backtrace_count - s_backtrace_index] = (void *)0;
        }

#if defined(def_hwport_leak_detective_magic_code)
        s_header->m_magic_code = def_hwport_leak_detective_magic_code;
#endif

        s_header->m_trailer->m_this = s_header;
#if defined(def_hwport_leak_detective_magic_code)
        s_header->m_trailer->m_magic_code = def_hwport_leak_detective_magic_code;
#endif

        /* prepend linked-list */
        if(g_hwport_leak_detective_info.m_head == ((hwport_leak_detective_header_t *)0)) {
                g_hwport_leak_detective_info.m_tail = s_header;
        }
        else {
                s_header->m_next = g_hwport_leak_detective_info.m_head;
                g_hwport_leak_detective_info.m_head->m_prev = s_header;
        }
        g_hwport_leak_detective_info.m_head = s_header;

        (void)__hwport_leak_detective_update_statistics(+1, (int)s_header->m_size);

        return(s_new_i_ptr);
}

static void *__hwport_leak_detective_pre_free_handler(void *s_new_i_ptr, const void *s_caller)
{
        hwport_leak_detective_header_t *s_header;

        void *s_new_o_ptr;

        (void)s_caller;

        if(s_new_i_ptr == ((void *)0)) {
                return((void *)0);
        }

        s_header = hwport_peek_r(hwport_leak_detective_header_t *,s_new_i_ptr,g_hwport_leak_detective_info.m_header_size);
        s_new_o_ptr = (void *)s_header;

        /* verify header */
#if defined(def_hwport_leak_detective_magic_code)
        if(hwport_unlikely(s_header->m_magic_code != def_hwport_leak_detective_magic_code)) {
                (void)fprintf(stderr, "BROKEN DETECTED !!! (invalid header's magic code)\n");
        }
#endif

        /* verify trailer */
        if(hwport_unlikely(s_header != s_header->m_trailer->m_this)) {
                (void)fprintf(stderr, "BROKEN DETECTED !!! (difference header with trailer, %p ?= %p)\n", s_header, s_header->m_trailer->m_this);
        }
#if defined(def_hwport_leak_detective_magic_code)
        else if(hwport_unlikely(s_header->m_trailer->m_magic_code != def_hwport_leak_detective_magic_code)) {
                (void)fprintf(stderr, "BROKEN DETECTED !!! (invalid trailer's magic code)\n");
        }
#endif

        /* delete linked-list */
        if(s_header->m_prev == ((hwport_leak_detective_header_t *)0)) {
                g_hwport_leak_detective_info.m_head = s_header->m_next;
        }
        else {
                s_header->m_prev->m_next = s_header->m_next;
        }
        if(s_header->m_next == ((hwport_leak_detective_header_t *)0)) {
                g_hwport_leak_detective_info.m_tail = s_header->m_prev;
        }
        else {
                s_header->m_next->m_prev = s_header->m_prev;
        }

        /* memwipe trailer */
        (void)memset((void *)s_header->m_trailer, 0, g_hwport_leak_detective_info.m_trailer_size);

        /* memwipe header */
        (void)memset((void *)s_header, 0, g_hwport_leak_detective_info.m_header_size);

        (void)__hwport_leak_detective_update_statistics(-1, -((int)s_header->m_size));

        return(s_new_o_ptr);
}

static void __hwport_leak_detective_post_free_handler(void *s_new_o_ptr, const void *s_caller)
{
        (void)s_new_o_ptr;
        (void)s_caller;
}

static void *hwport_leak_detective_malloc_hook(size_t s_size, const void *s_caller)
{
        size_t s_modified_size;
        void *s_new_o_ptr;
        void *s_new_i_ptr;

        hwport_leak_detective_restore_hook();

        s_modified_size = __hwport_leak_detective_pre_alloc_handler(s_size, s_caller);
        s_new_o_ptr = malloc(s_modified_size);
        s_new_i_ptr = __hwport_leak_detective_post_alloc_handler(s_new_o_ptr, s_size, s_modified_size, s_caller);

        hwport_leak_detective_save_hook();

#if def_hwport_leak_detective_debug_call_hook != 0L
        (void)fprintf(
                stderr,
                "[%-40s] (%5d) %p = malloc(%lu[%lu]) /* usable=%lu */\n",
                __hwport_leak_detective_get_symbol(s_caller, (const char **)0, (const char **)0),
                g_hwport_leak_detective_info.m_count,
                s_new_i_ptr,
                (unsigned long)s_size,
                (unsigned long)s_modified_size,
                (unsigned long)malloc_usable_size(s_new_o_ptr)
        );
#endif

        hwport_leak_detective_set_hook();

        return(s_new_i_ptr);
}

static void *hwport_leak_detective_realloc_hook(void *s_old_i_ptr, size_t s_size, const void *s_caller)
{
        size_t s_modified_size;
        void *s_old_o_ptr;
        void *s_new_o_ptr;
        void *s_new_i_ptr;

        hwport_leak_detective_restore_hook();

        if(s_old_i_ptr == ((void *)0)) { /* like malloc */
                s_modified_size = __hwport_leak_detective_pre_alloc_handler(s_size, s_caller);
                s_new_o_ptr = malloc(s_modified_size);
        }
        else {
                if(s_size <= ((size_t)0u)) { /* like free */
                        s_modified_size = (size_t)0u;
                        s_old_o_ptr = __hwport_leak_detective_pre_free_handler(s_old_i_ptr, s_caller);
                        free(s_old_o_ptr);
                        s_new_o_ptr = (void *)0;
                }
                else {
                        s_modified_size = __hwport_leak_detective_pre_alloc_handler(s_size, s_caller);
                        s_old_o_ptr = __hwport_leak_detective_pre_free_handler(s_old_i_ptr, s_caller);
                        s_new_o_ptr = realloc(s_old_o_ptr, s_modified_size);
                }

                __hwport_leak_detective_post_free_handler(s_old_o_ptr, s_caller);
        }
        s_new_i_ptr = __hwport_leak_detective_post_alloc_handler(s_new_o_ptr, s_size, s_modified_size, s_caller);

        hwport_leak_detective_save_hook();

#if def_hwport_leak_detective_debug_call_hook != 0L
        (void)fprintf(
                stderr,
                "[%-40s] (%5d) %p = realloc(%p, %lu[%lu])\n",
                __hwport_leak_detective_get_symbol(s_caller, (const char **)0, (const char **)0),
                g_hwport_leak_detective_info.m_count,
                s_new_i_ptr,
                s_old_i_ptr,
                (unsigned long)s_size,
                (unsigned long)s_modified_size
        );
#endif

        hwport_leak_detective_set_hook();

        return(s_new_i_ptr);
}

static void *hwport_leak_detective_memalign_hook(size_t s_alignment_size, size_t s_size, const void *s_caller)
{
        size_t s_modified_size;
        void *s_new_o_ptr;
        void *s_new_i_ptr;

        hwport_leak_detective_restore_hook();

        s_modified_size = __hwport_leak_detective_pre_alloc_handler(__hwport_alignment_size(s_size, s_alignment_size), s_caller);
        s_new_o_ptr = malloc(s_modified_size);
        s_new_i_ptr = __hwport_leak_detective_post_alloc_handler(s_new_o_ptr, s_size, s_modified_size, s_caller);

        hwport_leak_detective_save_hook();

#if def_hwport_leak_detective_debug_call_hook != 0L
        (void)fprintf(
                stderr,
                "[%-40s] (%5d) %p = memalign(%lu, %lu[%lu]) /* usable=%lu */\n",
                __hwport_leak_detective_get_symbol(s_caller, (const char **)0, (const char **)0),
                g_hwport_leak_detective_info.m_count,
                s_new_i_ptr,
                (unsigned long)s_alignment_size,
                (unsigned long)s_size,
                (unsigned long)s_modified_size,
                (unsigned long)malloc_usable_size(s_new_o_ptr)
        );
#endif

        hwport_leak_detective_set_hook();

        return(s_new_i_ptr);
}

static void hwport_leak_detective_free_hook(void *s_new_i_ptr, const void *s_caller)
{
        void *s_new_o_ptr;

        hwport_leak_detective_restore_hook();

        s_new_o_ptr = __hwport_leak_detective_pre_free_handler(s_new_i_ptr, s_caller);
        free(s_new_o_ptr);
        __hwport_leak_detective_post_free_handler(s_new_o_ptr, s_caller);

        hwport_leak_detective_save_hook();

#if def_hwport_leak_detective_debug_call_hook != 0L
        (void)fprintf(
                stderr,
                "[%-40s] (%5d) free(%p)\n",
                __hwport_leak_detective_get_symbol(s_caller, (const char **)0, (const char **)0),
                g_hwport_leak_detective_info.m_count,
                s_new_i_ptr
        );
#endif

        hwport_leak_detective_set_hook();
}

static void hwport_leak_detective_after_morecore_hook(void)
{
        hwport_leak_detective_restore_hook();

        hwport_leak_detective_save_hook();

#if def_hwport_leak_detective_debug_call_hook != 0L
        (void)fprintf(
                stderr,
                "[%-40s] (%5d) after_morecore()\n",
                "",
                g_hwport_leak_detective_info.m_count
        );
#endif

        hwport_leak_detective_set_hook();
}

static void hwport_leak_detective_save_hook(void)
{
        /* save */
        g_hwport_leak_detective_info.m_malloc = __malloc_hook;
        g_hwport_leak_detective_info.m_realloc = __realloc_hook;
        g_hwport_leak_detective_info.m_memalign = __memalign_hook;
        g_hwport_leak_detective_info.m_free = __free_hook;
        g_hwport_leak_detective_info.m_after_morecore = __after_morecore_hook;
}

static void hwport_leak_detective_restore_hook(void)
{
        /* restore */
        __after_morecore_hook = g_hwport_leak_detective_info.m_after_morecore;
        __free_hook = g_hwport_leak_detective_info.m_free;
        __memalign_hook = g_hwport_leak_detective_info.m_memalign;
        __realloc_hook = g_hwport_leak_detective_info.m_realloc;
        __malloc_hook = g_hwport_leak_detective_info.m_malloc;
}

static void hwport_leak_detective_set_hook(void)
{
        /* set */
        __malloc_hook = hwport_leak_detective_malloc_hook;
        __realloc_hook = hwport_leak_detective_realloc_hook;
        __memalign_hook = hwport_leak_detective_memalign_hook;
        __free_hook = hwport_leak_detective_free_hook;
        __after_morecore_hook = hwport_leak_detective_after_morecore_hook;
}

static void hwport_leak_detective_malloc_initialize_hook(void)
{
        hwport_leak_detective_save_hook();
        hwport_leak_detective_set_hook();
}

static void hwport_leak_detective_malloc_deinitialize_hook(void)
{
        hwport_leak_detective_restore_hook();
}

void hwport_leak_detective_report(void)
{
        hwport_leak_detective_header_t *s_header;

        int s_backtrace_index;

        const char *s_description;
        const char *s_symbol_name;
        const char *s_filename;

        for(s_header = g_hwport_leak_detective_info.m_head;s_header != ((hwport_leak_detective_header_t *)0);s_header = s_header->m_next) {
                (void)fprintf(
                        stderr,
                        "* allocated pointer is %p (wrapper=%p, size=%lu)\n",
                        hwport_peek(s_header, g_hwport_leak_detective_info.m_header_size),
                        s_header,
                        (unsigned long)s_header->m_size
                );


                if(s_header->m_backtrace == ((void **)0)) {
                        continue;
                }

                /* white list filter */
                for(s_backtrace_index = 0;;s_backtrace_index++) {
                        if(s_header->m_backtrace[s_backtrace_index] == ((void *)0)) {
                                break;
                        }

                        s_description = __hwport_leak_detective_get_symbol(
                                s_header->m_backtrace[s_backtrace_index],
                                (const char **)(&s_symbol_name),
                                (const char **)(&s_filename)
                        );

                        if(s_symbol_name != ((const char *)0)) {
#if 1L
                                if(strcmp(s_symbol_name, "dlopen") == 0) {
                                        break;
                                }
#endif
#if 1L
                                if(strcmp(s_symbol_name, "setlocale") == 0) {
                                        break;
                                }
#endif
#if 1L
                                if(strcmp(s_symbol_name, "getpwuid") == 0) {
                                        break;
                                }
#endif
                        }
                }
                if(s_header->m_backtrace[s_backtrace_index] != ((void *)0)) {
                        continue;
                }

                (void)__hwport_dump(
                        1,
                        hwport_peek(s_header, g_hwport_leak_detective_info.m_header_size),
                        (s_header->m_size > ((size_t)16u)) ? ((size_t)16u) : s_header->m_size
                );

                /* backtrace dump */
                for(s_backtrace_index = 0;;s_backtrace_index++) {
                        if(s_header->m_backtrace[s_backtrace_index] == ((void *)0)) {
                                break;
                        }

                        s_description = __hwport_leak_detective_get_symbol(
                                s_header->m_backtrace[s_backtrace_index],
                                (const char **)(&s_symbol_name),
                                (const char **)(&s_filename)
                        );

                        (void)fprintf(
                                stderr,
                                "  %02d - %p - %s\n",
                                s_backtrace_index + 1,
                                s_header->m_backtrace[s_backtrace_index],
                                s_description
                        );
                }
        }
}

void hwport_leak_detective_init(void)
{
        int s_reference_count;

        /* can unused function */
        (void)__hwport_dump_buffer;
        (void)__hwport_dump;

        s_reference_count = __sync_fetch_and_add(&g_hwport_leak_detective_info.m_reference_count, 1);
        if(s_reference_count == 0) {
#if 0L /* deprecated ? */
                g_hwport_leak_detective_info.m_malloc_initialize = __malloc_initialize_hook;
                __malloc_initialize_hook = hwport_leak_detective_malloc_initialize_hook;
#else /* set hook */
                hwport_leak_detective_malloc_initialize_hook();
#endif

                (void)fprintf(
                        stderr,
                        "Initializing hooking ... (pid=%ld)\n",
                        (long)getpid()
                );
                (void)fflush(stdout);
                (void)fflush(stderr);
        }
        else {
                (void)fprintf(
                        stderr,
                        "Re-initializing hooking ... (pid=%ld)\n",
                        (long)getpid()
                );
        }
}

void hwport_leak_detective_deinit(void)
{
        int s_reference_count;

        s_reference_count = __sync_sub_and_fetch(&g_hwport_leak_detective_info.m_reference_count, 1);
        if(hwport_unlikely(s_reference_count < 0)) {
                (void)fprintf(stderr,
                        "Exited hooking ... (pid=%ld, count=%d, size=%d)\n",
                        (long)getpid(),
                        g_hwport_leak_detective_info.m_count,
                        g_hwport_leak_detective_info.m_size
                );
                (void)fflush(stdout);
                (void)fflush(stderr);
        }
        else if(s_reference_count == 0) {
                (void)fprintf(stderr,
                        "De-initializing hooking ... (pid=%ld, count=%d, size=%d)\n",
                        (long)getpid(),
                        g_hwport_leak_detective_info.m_count,
                        g_hwport_leak_detective_info.m_size
                );
                (void)fflush(stdout);
                (void)fflush(stderr);

                hwport_leak_detective_malloc_deinitialize_hook();
#if 0L /* deprecated ? */
                __malloc_initialize_hook = g_hwport_leak_detective_info.m_malloc_initialize;
#endif

                hwport_leak_detective_report();
        }
        else {
                (void)fprintf(stderr,
                        "Decrement-reference hooking ... (pid=%ld, count=%d, size=%d)\n",
                        (long)getpid(),
                        g_hwport_leak_detective_info.m_count,
                        g_hwport_leak_detective_info.m_size
                );
        }
}

/* ---- */

#endif

/* vim: set expandtab: */
/* End of source */



</body>
</html>



아래 예제소스는 기존 할당자를 쓰되 메모리 누수를 감지하는 목적으로 caller 및 카운팅을 추가적으로 관리하는 구현입니다.

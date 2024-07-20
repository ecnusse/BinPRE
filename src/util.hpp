#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <cxxabi.h> 
#include "config.hpp"
#include <iostream> 
#include <iomanip>  
#include <sstream>


namespace monitor {

    bool _start = false;
    bool _end   = false;

    inline bool valid() {
        return _start && !_end;
    } 

    inline bool invalid(int threadId) {
        return !_start || _end || (config::thread_flag && threadId != config::threadId);
    } 

    inline void start() {
        printf("instumentation start\n");
        _start = true;
    }

    inline void end() {
        printf("instumentation end\n");
        _end = true;
    }
} // monitor namespace end

namespace logger {


    bool _debug = false;
    FILE *_dout = stdout;
    bool _verbose = false;
    FILE *_vout = stdout;
    bool _info = false;
    FILE *_iout = stdout;
    bool _loopsinfo = false;
    FILE *_lout = stdout;
    bool _formatinfo = false;
    FILE *_fout = stdout;
    bool _datainfo = false;
    FILE *_daout = stdout;

    void setDebug(bool b, FILE *out=stdout) {_debug = b; _dout = out;}
    void setVerbose(bool b, FILE *out=stdout) {_verbose = b; _vout = out;}
    void setInfo(bool b, FILE *out=stdout) {_info = b; _iout = out;}
    void setLoopsInfo(bool b, FILE *out=stdout) {_loopsinfo = b; _lout = out;}
    void setFormatInfo(bool b, FILE *out=stdout) {_formatinfo = b; _fout = out;}
    void setDataInfo(bool b, FILE *out=stdout) {_datainfo = b; _daout = out;}

    void debug(const char *fmt, ...) {
        if (!_debug) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_dout, fmt, arg);
        va_end(arg);
        if (config::isFlush) fflush(_dout);
    }

    void verbose(const char *fmt, ...) {
        if (!_verbose) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_vout, fmt, arg);
        va_end(arg);
        if (config::isFlush) fflush(_vout);
    }

    void info(const char *fmt, ...) {
        if (!_info) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_iout, fmt, arg);
        va_end(arg);
        if (config::isFlush) fflush(_iout);
    }
    void loopsinfo(const char *fmt, ...) {
        if (!_loopsinfo) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_lout, fmt, arg);
        va_end(arg);
        if (config::isFlush) fflush(_lout);
    }
    void formatinfo(const char *fmt, ...) {
        if (!_formatinfo) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_fout, fmt, arg);
        va_end(arg);
        if (config::isFlush) fflush(_fout);
    }
    void datainfo(const char *fmt, ...) {
        if (!_datainfo) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_daout, fmt, arg);
        va_end(arg);
        if (config::isFlush) fflush(_daout);
    }

    void print(const char *fmt, ...) {
        if (!config::print) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(stderr, fmt, arg);
        va_end(arg);
        if (config::isFlush) fflush(stdout);
    }

    void printline(const unsigned char *start, size_t size) {
        if (!config::print) return;
        size = std::min(size, (size_t)128);
        logger::formatinfo("[Message]\tsize %lx:\t", size);
        fprintf(stderr, "size %lx:\t", size);
        for (size_t i = 0; i < size; ++i) {
            logger::formatinfo("(%x) ",*start);
            fprintf(stderr, "(%x) ", *start++);
        }
        logger::formatinfo("\n");
        fprintf(stderr, "\n");
    }

} // log namespace end


namespace debug {

    const char *assembly = NULL;

    unsigned long address = 0;

    void log(unsigned long address_, const char *assembly_) {
        address = address_;
        assembly = assembly_;
    }

    void error() {
        printf("error : %lx\t:%s\n", address, assembly);
    }


} // end of namespace debug


namespace util {

    PIN_LOCK lock;

    class LockGuard {
    public:
        LockGuard(int threadId) {
            PIN_GetLock(&lock, threadId+1);
        }

        ~LockGuard() {
            PIN_ReleaseLock(&lock);
        }
    };


    const REG regs[] = {
        REG_RAX, REG_EAX,  REG_AX,   REG_AH,   REG_AL,        // 10, 56, 29, 28, 27,
        REG_RBX, REG_EBX,  REG_BX,   REG_BH,   REG_BL,        //  7, 53, 38, 37, 36,
        REG_RCX, REG_ECX,  REG_CX,   REG_CH,   REG_CL,        //  9, 55, 32, 31, 30,
        REG_RDX, REG_EDX,  REG_DX,   REG_DH,   REG_DL,        //  8, 54, 35, 34, 33,
        REG_RDI, REG_EDI,  REG_DI,   REG_DIL,  REG_INVALID_,  //  3, 45, 41, 46,  0,
        REG_RSI, REG_ESI,  REG_SI,   REG_SIL,  REG_INVALID_,  //  4, 47, 40, 48,  0,
        REG_R8,  REG_R8D,  REG_R8W,  REG_R8B,  REG_INVALID_,  // 11, 61, 60, 59,  0,
        REG_R9,  REG_R9D,  REG_R9W,  REG_R9B,  REG_INVALID_,  // 12, 64, 63, 62,  0,
        REG_R10, REG_R10D, REG_R10W, REG_R10B, REG_INVALID_,  // 13, 67, 66, 65,  0,
        REG_R11, REG_R11D, REG_R11W, REG_R11B, REG_INVALID_,  // 14, 70, 69, 68,  0,
        REG_R12, REG_R12D, REG_R12W, REG_R12B, REG_INVALID_,  // 15, 73, 72, 71,  0,
        REG_R13, REG_R13D, REG_R13W, REG_R13B, REG_INVALID_,  // 16, 76, 75, 74,  0,
        REG_R14, REG_R14D, REG_R14W, REG_R14B, REG_INVALID_,  // 17, 79, 78, 77,  0,
        REG_R15, REG_R15D, REG_R15W, REG_R15B, REG_INVALID_,   // 18, 82, 81, 80,  0
        REG_RSP, REG_ESP,  REG_SP, REG_INVALID_, REG_INVALID_,
        REG_RBP, REG_EBP,  REG_BP, REG_INVALID_, REG_INVALID_
    };

    const char *regNames[] = {//only used by debug
        "RAX",     "EAX",     "AX",      "AH",      "AL",      
        "RBX",     "EBX",     "BX",      "BH",      "BL",      
        "RCX",     "ECX",     "CX",      "CH",      "CL",     
        "RDX",     "EDX",     "DX",      "DH",      "DL",      
        "RDI",     "EDI",     "DI",      "DIL",     "Invalid", 
        "RSI",     "ESI",     "SI",      "SIL",     "Invalid", 
        "R8",      "R8D",     "R8W",     "R8B",     "Invalid",
        "R9",      "R9D",     "R9W",     "R9B",     "Invalid", 
        "R10",     "R10D",    "R10W",    "R10B",    "Invalid", 
        "R11",     "R11D",    "R11W",    "R11B",    "Invalid", 
        "R12",     "R12D",    "R12W",    "R12B",    "Invalid", 
        "R13",     "R13D",    "R13W",    "R13B",    "Invalid", 
        "R14",     "R14D",    "R14W",    "R14B",    "Invalid", 
        "R15",     "R15D",    "R15W",    "R15B",    "Invalid",
        "RSP",     "ESP",     "SP",      "Invalid",  "Invalid",
        "RBP",     "EBP",     "BP",      "Invalid",  "Invalid"
    };


    bool valiReg(REG reg) {
        if (reg <= 0 || reg >= 100) return false;
        for (uint16_t i = 0; i < sizeof(util::regs) / sizeof(REG); ++i) {
            if (util::regs[i] == reg) {
                return true;
            }
        }
        return false;
    }

    /* find REG id's 'regs index' */
    uint16_t indexOfReg(REG id) { 
        for (uint16_t i = 0; i < sizeof(util::regs) / sizeof(REG); ++i) {
            if (util::regs[i] == id) {
                return i;
            }
        }
        printf("error index of reg: %d\n", id);
        return -1;
    }

    REG rawReg(REG reg) {
        int index = indexOfReg(reg);
        index -= index % 5;
        return regs[index];
    }


    inline ADDRINT Value(UINT64 mem, size_t size) { 
        ADDRINT value;
        PIN_SafeCopy((void*)(&value), (void *)mem, sizeof(ADDRINT));
        /* ensure return specified size value*/
        switch (size) {
            case 1:     value &= 0xff;          break;
            case 2:     value &= 0xffff;        break;
            case 4:     value &= 0xffffffff;    break;
        }
        return value;
    }

    std::string printBuffer(uint64_t buffer, size_t length) {
        const char* buffer_ptr = reinterpret_cast<const char*>(buffer);
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; i++) {
            ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(buffer_ptr[i]));
        }
        return ss.str();

    }


    inline void ValueCopy(void *dst, uint64_t addr, size_t size) {
        PIN_SafeCopy(dst, (void *)addr, size);
    }

    #define swap16(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

    #define swap32(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                    ((((unsigned long)(n) & 0xFF00)) << 8) | \
                    ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                    ((((unsigned long)(n) & 0xFF000000)) >> 24))

    #define swap64(n) (((((unsigned long long)(n) & 0xFF)) << 56) | \
                    ((((unsigned long long)(n) & 0xFF00)) << 40) | \
                    ((((unsigned long long)(n) & 0xFF0000)) << 24) | \
                    ((((unsigned long long)(n) & 0xFF000000)) << 8) | \
                    ((((unsigned long long)(n) & 0xFF00000000)) >> 8) | \
                    ((((unsigned long long)(n) & 0xFF0000000000)) >> 24) | \
                    ((((unsigned long long)(n) & 0xFF000000000000)) >> 50) | \
                    ((((unsigned long long)(n) & 0xFF00000000000000)) >> 56)) 

    uint64_t swap(uint64_t value, int size) {
        if (size == 1) return value;
        if (size == 2) return swap16(value);
        if (size == 3) return swap32(value) >> 8;
        if (size == 4) return swap32(value);
        if (size == 6) return swap64(value) >> 16;
        if (size == 8) return swap64(value);
        printf("error swap value size: %d\n", size);
        return value;
    }

    const char *nums(int start, int size) {
        static char buffer[256];
        static int index = 0;
        char *buf = buffer + index;
        const int block = 32;

        int n = snprintf(buf, block, "%d", start);
        for (int i = start + 1; i < start + size; ++i) {
            buf[n++] = ',';
            n += snprintf(buf + n, block - n, "%d", i);
        }
        buf[n] = 0;
        index = (index + block) % 256; 
        return buf;
    }

    void myassert(bool a, const char *info=0) {
    if (!a) {
        // logger::debug("assert error %s\n", (info > 0) ? info: "");
    }
    }

    const char *demangle(const char *name) {
        const static int maxsize = 1024;
        static char buf[maxsize+4];
        int status;
        int size = strlen(name);
        char *realname;
        strncpy(buf, name, maxsize - 1);
        buf[maxsize - 1] = 0;
        bool isPlt = size > 4 && strcmp(name + size - 4, "@plt") == 0;
        if (isPlt) buf[size - 4] = 0;
        realname = abi::__cxa_demangle(buf, 0, 0, &status);
        if (!status) {
            strncpy(buf, realname, maxsize - 1);
            buf[maxsize - 1] = 0;
        }
        if (isPlt) {
            strcpy(buf + strlen(buf), "@plt");
        }
        free(realname);
        return buf;
    }


    const char *displayRegs(CONTEXT *ctx) {
        static char buf[512];
        int n = 0;
        n += sprintf(buf + n, "+--------------------------------------------------------------------------+\n");
        n += sprintf(buf + n, " RAX = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX));
        n += sprintf(buf + n, " RBX = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX));
        n += sprintf(buf + n, " RCX = 0x%-16lx\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX));
        n += sprintf(buf + n, " RDX = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX));
        n += sprintf(buf + n, " RDI = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI));
        n += sprintf(buf + n, " RSI = 0x%-16lx\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI));
        n += sprintf(buf + n, " RBP = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP));
        n += sprintf(buf + n, " RSP = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP));
        n += sprintf(buf + n, " RIP = 0x%-16lx\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP));
        n += sprintf(buf + n, "+--------------------------------------------------------------------------+\n");
        buf[n] = 0;
        return buf;
    }


} // end of namespace util


namespace filter {

    const char *entry = "entry";
    const char *exit = "exit";

    bool read(int fd, uint64_t addr, ssize_t size) {

        bool ret = (fd <= 2 || fd > 10 || addr <= 0x100 || size <= 2 || size >= 131073) // default pass rule:size >=1024
            || (config::read_size_flag && (size < config::read_size_min || size > config::read_size_max))
            || (config::read_fd_flag && (fd < config::read_fd_min || fd > config::read_fd_max));
        
        fprintf(stderr, "fd/socket: %d\n",fd);
        return ret;
    }


    bool testfunc(const std::string& name) {
        size_t n = sizeof(config::tetfuncs) / sizeof(const char *);

        for (size_t i = 0; i < n; ++i) {
            if (name.find(config::tetfuncs[i]) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool blackfunc(const std::string& name) {
        size_t n = sizeof(config::blackfuncs) / sizeof(const char *);

        for (size_t i = 0; i < n; ++i) {
            if (name.find(config::blackfuncs[i]) != std::string::npos) {
                return true;
            }
        }
        return false;
    }


    bool libs(const std::string &name) {
        size_t n = sizeof(config::libs) / sizeof(const char *);

        for (size_t i = 0; i < n; ++i) {
            if (name.find(config::libs[i]) != std::string::npos) {
                return true;
            }
        }
        return false;
    }


    bool taint_start() {
        if (!config::use_interactive) return true;
        static bool ret = false;
        if (ret) return ret;
        printf("taint start?[y/n]");
        char c = getchar();
        getchar(); // for \n
        if (c == 'y') {
            printf("taint start\n");
            ret = true;
            return true;
        }
        return false;
    }

}// end of namespace filter

#endif
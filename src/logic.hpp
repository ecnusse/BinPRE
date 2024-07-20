#ifndef _TAINTLOGIC_H
#define _TAINTLOGIC_H

#include "pin.H"
#include "taintengine.hpp"
#include "util.hpp"
#include "pinobject.hpp"
#include <iostream> 
#include <bitset>   


std::vector<std::vector<std::string> > functraces;
std::vector<int> threadIds;


void printTrace(int index) {
    std::vector<std::string>::iterator it;
    for (it = functraces[index].begin(); it != functraces[index].end(); ++it) {
        logger::debug("%s -> ", (*it).c_str());
    }
    logger::debug("\n");
}

void enterTrace(int threadId, const std::string* name) {
    if (!config::traceLog) return;
    const int size = threadIds.size();
    int index = 0;
    for (int i = 0; i < size; ++i) {
        if (threadIds[i] == threadId) {
            index = i;
            break;
        }
    }
    if (index == size) {//curr threadId is new
        threadIds.push_back(threadId);//add it into threadId table
        functraces.push_back(std::vector<std::string>());//Initialize function call chain for curr threadId
    }
    //update function call chain for curr threadId 'index'
    functraces[index].push_back(*name);
}

void exitTrace(int threadId, const std::string* name) {
    if (!config::traceLog) return;
    const int size = threadIds.size();
    int index = 0;
    for (int i = 0; i < size; ++i) {
        if (threadIds[i] == threadId) {
            index = i;
            break;
        }
    }
    if (index == size) { 
        // logger::print("trace exit error\n"); 
        return;
    }
    // while (!functraces[index].empty() && functraces[index].back() != *name) {
    //     functraces[index].pop_back();    
    // }
    util::myassert(functraces[index].back() == *name);
    functraces[index].pop_back();
}

void function_entry(int threadId, const std::string* name, uint64_t begin, uint64_t end, uint64_t ret) {
    /* if name == 'main, start monitor*/
    if (*name == config::start_entry) monitor::start();
    if (monitor::invalid(threadId)) return;
    /* record function entry infomation*/
    enterTrace(threadId, name);
    logger::info("Function\t%d\tenter\t%s\t(%lx,%lx,%lx)\n", threadId, util::demangle(name->c_str()), begin, end, ret);
}


void function_exit(int threadId, const std::string* name) {
    if (monitor::invalid(threadId)) return;
    exitTrace(threadId, name);
    logger::info("Function\t%d\texit \t%s\n", threadId, util::demangle(name->c_str()));
    if (*name == config::start_entry) monitor::end();
}

void print_functions(const std::string *name, uint64_t para1, uint64_t para2, uint64_t para3, uint64_t para4) {
    // logger::verbose("--------------");
    // logger::verbose("%s: %lx %lx %lx %lx\t%s\n", util::demangle(name->c_str()), para1, para2, para3, para4, name->c_str());
}

void print_instructions0(const std::string *name, uint64_t address) {
    // logger::verbose("InsADDRESS#########filter!!!");
    // logger::verbose("%p: %s\n", address, name->c_str());
}

void print_instructions1(const std::string *name, uint64_t address, const CONTEXT *ctxt, REG r1, REG r2, uint64_t m1, uint64_t m2) {
    static char buf[64];
    int n = 0;
    /* check whether every arg is existed. Then turn them into 'string' format and store them into buff*/
    if (util::valiReg(r1)) {
        n += sprintf(buf + n, " reg(%d, %lx) ", r1, PIN_GetContextReg(ctxt, util::rawReg(r1)));
    }
    if (util::valiReg(r2)) {
        n += sprintf(buf + n, " reg(%d, %lx) ", r2, PIN_GetContextReg(ctxt, util::rawReg(r2)));
    }
    if (m1 > 0) {
        n += sprintf(buf + n, " mem(%lx, %lx) ", m1, util::Value(m1, 8));
    }
    if (m2 > 0) {
        n += sprintf(buf + n, " mem(%lx, %lx) ", m2, util::Value(m2, 8));
    }
    buf[n] = 0;
}



static int cur_sock = -1;


void read_point(const char *point, int fd, uint64_t buffer, size_t length, ssize_t ret) {
    static int _fd;
    static uint64_t _buffer;
    static size_t _length;
    
    if (!monitor::valid() || !filter::taint_start()) return;
    /* Save the file descriptor, buffer address, and data length.*/
    if (point == filter::entry) {
        _fd = fd;
        _buffer = buffer;
        _length = length;
    }
    /* Check if the 'read' is valid*/
    if (filter::read(_fd, _buffer, _length)) return;
    
}


void write_point(const char *point, int fd, uint64_t buffer, size_t length, ssize_t ret) {
    static int _fd;
    // static uint64_t _buffer;
    // static size_t _length;
    if (monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _fd = fd;
        // _buffer = buffer;
        // _length = length;
    }
    if (_fd != cur_sock) return;

    
}


void send_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, ssize_t ret) {
    static int _socket;
    // static uint64_t _buffer;
    // static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        // _buffer = buffer;
        // _length = length;
    }

    if (_socket != cur_sock) return;
    
}


void sendto_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, struct sockaddr *address, socklen_t address_len, ssize_t ret){
    static int _socket;
    // static uint64_t _buffer;
    // static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        // _buffer = buffer;
        // _length = length;
    }

    if (_socket != cur_sock) return;

}


void sendmsg_point(const char *point, int socket, struct msghdr* mhdr, int flags, ssize_t ret) {
    static int _socket;
    // static uint64_t _buffer;
    // static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;
    if (point == filter::entry) {
        _socket = socket;
        // _buffer = (uint64_t) mhdr->msg_iov[0].iov_base;
        // _length = mhdr->msg_iov->iov_len;
    }

    if (_socket != cur_sock) return;

}


void recv_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, ssize_t ret) {
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    // static int _flags;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }
    if (filter::read(_socket, _buffer, _length)) return;

    if (point == filter::exit) {
        cur_sock = _socket;
        if (TaintEngine::isTainted(REG_RDX)) { // log if size is tainted
            logger::info("LENGTH\t%s\n", TaintEngine::offsets(REG_RDX));
        }
        logger::info("recv_point taint\n");//
        /*Tag Taint */
        TaintEngine::Init(_buffer, ret);
    }
}


void recvfrom_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len, ssize_t ret){
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    // static int _flags;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }

    if (filter::read(_socket, _buffer, _length)) return;
    
    if (point == filter::exit) {
        cur_sock = _socket;
        if (TaintEngine::isTainted(REG_RDX)) { // log if size is tainted
            logger::info("LENGTH\t%s\n", TaintEngine::offsets(REG_RDX));
        }
    }
}


void recvmsg_point(const char *point, int socket, struct msghdr* mhdr, int flags, ssize_t ret) {
    static int _socket;
    // static struct msghdr* _mhdr;
    // static int _flags;
    static uint64_t _buffer;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        // _mhdr = mhdr;
        // _flags = flags;
        _buffer = (uint64_t) mhdr->msg_iov[0].iov_base;
        // size_t len = message->msg_iovlen;
    }

    if (point == filter::exit) {
        ssize_t _length = ret;
        if (filter::read(_socket, _buffer, _length)) return;
        cur_sock = _socket;
        if (_length > 0) {
            logger::info("recvmsg_point taint\n");//
            TaintEngine::Init(_buffer, _length);
        }
    }
}


void memcpy_point(const char *point, uint64_t dst, uint64_t src, size_t size) {
    if (!monitor::valid()) return;
    // logger::info("Trace Copy:\t%lx\t%lx\t%d\n", dst, src, size);
    for (size_t i = 0; i < size;) {
        /* if has taint (from src-dst)*/
        if (TaintEngine::isTainted(src + i)) {
            // size_t s = i;//taint start
            /* Find taint Interval*/
            while (i < size && TaintEngine::isTainted(src + i)) ++i;
        } else {
            ++i;
        }
    }
}


void memmove_point(const char *point, uint64_t dst, uint64_t src, size_t size) {
    if (!monitor::valid()) return;
    // logger::info("Trace Copy:\t%lx\t%lx\t%d\n", dst, src, size);
    for (size_t i = 0; i < size;) {
        if (TaintEngine::isTainted(src + i)) {
            while (i < size && TaintEngine::isTainted(src + i)) ++i;
        } else {
            ++i;
        }
    }
}


// reg <- mem
void ReadMem(int threadId, const std::string* assembly, unsigned long address, REG reg, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    ADDRINT value = util::Value(mem, size);//Obtain MemR's Value
    /* Neither is tainted.*/
    if (!taint_w && !taint_r) {
        return;
    }
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);

    /* spread taint :reg <- mem */
    if (taint_r) { // retaint
        size = TaintEngine::move(reg, mem, size);

        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId, 
            TaintEngine::offsets(mem,size), TaintEngine::src(mem), value);
        
        
    } else if (taint_w && !taint_r) { // untaint
        TaintEngine::remove(reg);
    }
}

// mem <- reg
void WriteMem(int threadId, const std::string* assembly, unsigned long address, UINT64 mem, REG reg, ADDRINT value, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(mem);
    bool taint_r = TaintEngine::isTainted(reg);
    
    if (!taint_w && !taint_r) {
        return;
    }

    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    /* spread taint :reg <- mem */
    if (taint_r) {
        TaintEngine::move(mem, reg, size); // change src
        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId,  
            TaintEngine::offsets(reg), TaintEngine::src(reg), value);
    } else if (taint_w && !taint_r) { // untaint
        
        TaintEngine::remove(mem);
    }
}

// reg <- reg
void spreadReg(int threadId, const std::string* assembly, unsigned long address, REG reg_w, REG reg_r, ADDRINT value) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);

    if (!taint_w && !taint_r) {
        return;
    }
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    if (taint_r) { // retaint
        TaintEngine::move(reg_w, reg_r);

        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId, 
            TaintEngine::offsets(reg_r), TaintEngine::src(reg_r), value);
    } else if (taint_w && !taint_r) { // untaint
        TaintEngine::remove(reg_w);
    }
}

// mem <- mem
void spreadMem(int threadId, const std::string* assembly, unsigned long address, UINT64 mem_w, UINT64 mem_r, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(mem_w);
    bool taint_r = TaintEngine::isTainted(mem_r);
    ADDRINT value = util::Value(mem_r, size);
    logger::info("spreadMem size:%d\n",size);
    
    if (!taint_w && !taint_r) {
        return;
    }

    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    if (taint_r) { // retaint
        TaintEngine::move(mem_w, mem_r, size);

        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId, 
            TaintEngine::offsets(mem_r), TaintEngine::src(mem_r), value);
        
    } else if (taint_w && !taint_r) { // untaint
        TaintEngine::remove(mem_w);
    }
}


// reg <- imm
void deleteReg(int threadId, const std::string* assembly, unsigned long address, REG reg) {
    if (monitor::invalid(threadId)) return;

    if (TaintEngine::isTainted(reg)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);

        /* remove reg's taint*/
        TaintEngine::remove(reg);
    }
}

// mem <- imm
void deleteMem(int threadId, const std::string* assembly, unsigned long address, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);

        TaintEngine::remove(mem);
    }
}

// ReadMem callback functions is inserted
void InsertCall(Ins ins, REG reg, int mem) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMem, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,//insName, IARG_INST_PTR：inst addr。
        IARG_ADDRINT, reg,//reg addr
        IARG_MEMORYOP_EA, mem,//mem addr
        IARG_ADDRINT, ins.MemRSize(),//mem size
    IARG_END);

}

// WriteMem callback functions is inserted
void InsertCall(Ins ins, int mem, REG reg) {
    const std::string *insName = new std::string(ins.Name());

    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

// spreadMem callback functions is inserted
void InsertCall(Ins ins, int mem_w, int mem_r) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadMem,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem_w,
        IARG_MEMORYOP_EA, mem_r,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

// spreadReg callback functions is inserted
void InsertCall(Ins ins, REG reg_w, REG reg_r) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadReg,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR, 
        IARG_ADDRINT, reg_w,
        IARG_ADDRINT, reg_r,
        IARG_REG_VALUE, reg_r,
    IARG_END);
}

// delete mem
void InsertCall(Ins ins, int mem) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)deleteMem,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

// delete reg
void InsertCall(Ins ins, REG reg) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)deleteReg, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, reg,
    IARG_END);
}


// 3 Ops

// reg <- reg
void Op3RegReg(int threadId, const std::string* assembly, unsigned long address, int opcode, REG reg_w, REG reg_r, ADDRINT value_w, ADDRINT value_r) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);

    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(reg_w));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(reg_r));
    }
    buf[n] = 0;

    logger::info("Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);

    /* add & or : reg_w != reg_r -> merge taint */
    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR) && reg_w != reg_r) {
        /* merge(reg_w, reg_r) updates reg_w's taint size*/
        if (TaintEngine::merge(reg_w, reg_r)) {
            logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), 
                threadId,
                TaintEngine::offsets(reg_w), value_w);
        }
    } /* xor & sub : reg_w == reg_r -> merge taint */
    else if ((opcode == XED_ICLASS_XOR || opcode == XED_ICLASS_SUB) && reg_w == reg_r) {
        TaintEngine::remove(reg_w);
    }

}
void Op3RegReg_cmp(int threadId, const std::string* assembly, const std::string* next_assembly, unsigned long address, int opcode, REG reg_w, REG reg_r, ADDRINT value_w, ADDRINT value_r) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(reg_w));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(reg_r));
    }
    buf[n] = 0;
    logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);
    logger::info("CMP+JUMP_NEXT-Instruction : %s\n", 
            next_assembly->c_str());

    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR) && reg_w != reg_r) {
        /* only bit-adjacent taint can be merged, offset-adjacent cannot be merged*/
        if (TaintEngine::merge(reg_w, reg_r)) {
            logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), 
                threadId,
                TaintEngine::offsets(reg_w), value_w);
            logger::info("CMP+JUMP_NEXT-Instruction : %s\n", 
                next_assembly->c_str());
        }
    } else if ((opcode == XED_ICLASS_XOR || opcode == XED_ICLASS_SUB) && reg_w == reg_r) {
        TaintEngine::remove(reg_w);
    }

    
}

void InsertCallExtra(Ins ins, REG reg_w, REG reg_r) { // Reg Reg
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegReg, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR, 
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg_w,
        IARG_ADDRINT, reg_r,
        IARG_REG_VALUE, reg_w,
        IARG_REG_VALUE, reg_r,
    IARG_END);
}
void InsertCallExtra_cmp(Ins ins, REG reg_w, REG reg_r) { // Reg Reg
    const std::string *insName = new std::string(ins.Name());
    Ins next_ins = INS_Next(ins);
    const std::string *next_insName = new std::string(next_ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegReg_cmp, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_PTR, next_insName, IARG_INST_PTR, 
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg_w,
        IARG_ADDRINT, reg_r,
        IARG_REG_VALUE, reg_w,
        IARG_REG_VALUE, reg_r,
    IARG_END);
}

void Op3RegImm(int threadId, const std::string* assembly, unsigned long address, int opcode, REG reg, ADDRINT value, int imm) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(reg)) {
        
        // const char* offsets0 = TaintEngine::offsets(reg);
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        if (opcode == XED_ICLASS_SHL) {
            TaintEngine::shift(reg, imm);
        } else if (opcode == XED_ICLASS_SHR || opcode == XED_ICLASS_SAR || opcode == XED_ICLASS_ROR) {
            TaintEngine::shift(reg, -imm); 
            // ror uncheck
            // add ROL switch: rol ax
        } else if (opcode == XED_ICLASS_AND) { // and uncheck
            TaintEngine::and_(reg, imm);
        }
        
        logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
            address, assembly->c_str(), threadId,
            TaintEngine::offsets(reg), value);//TaintEngine::offsets(reg)
    }   
}
void Op3RegImm_cmp(int threadId, const std::string* assembly, const std::string* next_assembly, unsigned long address, int opcode, REG reg, ADDRINT value, int imm) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(reg)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        if (opcode == XED_ICLASS_SHL) {
            TaintEngine::shift(reg, imm);
        } else if (opcode == XED_ICLASS_SHR || opcode == XED_ICLASS_SAR || opcode == XED_ICLASS_ROR) {
            TaintEngine::shift(reg, -imm); 
            // ror uncheck
            // add ROL switch: rol ax
        } else if (opcode == XED_ICLASS_AND) { // and uncheck
            TaintEngine::and_(reg, imm);
        }
        
        logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p\n", 
            address, assembly->c_str(), threadId,
            TaintEngine::offsets(reg), value);
        logger::info("CMP+JUMP_NEXT-Instruction : %s\n", 
            next_assembly->c_str());
    }   
}

void InsertCallExtra(Ins ins, REG reg) { // Reg Imm
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegImm,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.valueImm(1),
    IARG_END);
}
void InsertCallExtra_cmp(Ins ins, REG reg) { // Reg Imm
    const std::string *insName = new std::string(ins.Name());
    Ins next_ins = INS_Next(ins);
    const std::string *next_insName = new std::string(next_ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegImm_cmp,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_PTR, next_insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.valueImm(1),
    IARG_END);
}

void Op3RegMem(int threadId, const std::string* assembly, unsigned long address, int opcode, REG reg, ADDRINT value_w, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    ADDRINT value_r = util::Value(mem, size);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(reg));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(mem));
    }
    buf[n] = 0;
    logger::info("Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);
    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR)) {
        if (TaintEngine::merge(reg, mem)) {
            logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), threadId,
                TaintEngine::offsets(reg), value_w);
        }
    }
}
void Op3RegMem_cmp(int threadId, const std::string* assembly, const std::string* next_assembly, unsigned long address, int opcode, REG reg, ADDRINT value_w, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    ADDRINT value_r = util::Value(mem, size);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(reg));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(mem));
    }
    buf[n] = 0;

    logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);
    logger::info("CMP+JUMP_NEXT-Instruction : %s\n", 
            next_assembly->c_str());
    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR)) {
        if (TaintEngine::merge(reg, mem)) {
            logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), threadId,
                TaintEngine::offsets(reg), value_w);
            logger::info("CMP+JUMP_NEXT-Instruction : %s\n", next_assembly->c_str());
        }
    }
}

void InsertCallExtra(Ins ins, REG reg, int mem) { // Reg Mem
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegMem,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}
void InsertCallExtra_cmp(Ins ins, REG reg, int mem) { // Reg Mem
    const std::string *insName = new std::string(ins.Name());
    Ins next_ins = INS_Next(ins);
    const std::string *next_insName = new std::string(next_ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegMem_cmp,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_PTR, next_insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

// add & or
void Op3MemReg(int threadId, const std::string* assembly, unsigned long address, int opcode, UINT64 mem, REG reg, ADDRINT value_r, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(mem);
    bool taint_r = TaintEngine::isTainted(reg);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    ADDRINT value_w = util::Value(mem, size);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(mem));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(reg));
    }
    buf[n] = 0;
    logger::info("Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);

    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR)) {
        if (TaintEngine::merge(mem, reg)) {
            logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), threadId,
                TaintEngine::offsets(mem), value_w);
        }
    }

}
void Op3MemReg_cmp(int threadId, const std::string* assembly, const std::string* next_assembly, unsigned long address, int opcode, UINT64 mem, REG reg, ADDRINT value_r, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(mem);
    bool taint_r = TaintEngine::isTainted(reg);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    ADDRINT value_w = util::Value(mem, size);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(mem));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(reg));
    }
    buf[n] = 0;

    logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);
    logger::info("CMP+JUMP_NEXT-Instruction : %s\n", 
            next_assembly->c_str());
    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR)) {
        if (TaintEngine::merge(mem, reg)) {
            logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), threadId,
                TaintEngine::offsets(mem), value_w);
            logger::info("CMP+JUMP_NEXT-Instruction : %s\n", 
            next_assembly->c_str());
        }
    }

}

void InsertCallExtra(Ins ins, int mem, REG reg) { // Mem Reg
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3MemReg,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.MemRSize(),//debug:MemWSize->MemRSize
    IARG_END);
}
void InsertCallExtra_cmp(Ins ins, int mem, REG reg) { // Mem Reg
    const std::string *insName = new std::string(ins.Name());
    Ins next_ins = INS_Next(ins);
    const std::string *next_insName = new std::string(next_ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3MemReg_cmp,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_PTR, next_insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

void Op3MemImm(int threadId, const std::string* assembly, unsigned long address, int opcode, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        ADDRINT value = util::Value(mem, size);


        logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
            address, assembly->c_str(), threadId,
            TaintEngine::offsets(mem), value);//size
    }
}
void Op3MemImm_cmp(int threadId, const std::string* assembly, const std::string* next_assembly, unsigned long address, int opcode, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        ADDRINT value = util::Value(mem, size);
 
        logger::info("CMP+JUMP-Instruction %p: %s\t%d\t%s\t%p\n", 
            address, assembly->c_str(), threadId,
            TaintEngine::offsets(mem), value);
        logger::info("CMP+JUMP_NEXT-Instruction : %s\n", 
            next_assembly->c_str());
        
    }
}


void InsertCallExtra(Ins ins, int mem) { // Mem Imm
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3MemImm,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),//debug:MemWSize->MemRSize
    IARG_END);
}
void InsertCallExtra_cmp(Ins ins, int mem) { // Mem Imm
    const std::string *insName = new std::string(ins.Name());
    Ins next_ins = INS_Next(ins);
    const std::string *next_insName = new std::string(next_ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3MemImm_cmp,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_PTR, next_insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

#endif
// taint logic end

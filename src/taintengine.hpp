#ifndef _TAINTENGINE_H
#define _TAINTENGINE_H

#include <cstdint>
#include <map>
#include <vector>
#include "util.hpp"

namespace TaintEngine {

// Taint Memory
class Inits {
   private:
    struct MemI {
        uint64_t start;
        size_t size;
        uint8_t bytes[config::maxsize];

        uint64_t begin() { return start; }

        uint64_t end() { return start + size; }

        bool valid(uint64_t addr) {
            return addr >= start && addr < start + size;
        }

        uint8_t value(size_t pos) { return bytes[pos]; }

        uint64_t value(uint64_t pos, size_t len, bool bigendian) {
            if (pos + len > size) {
                debug::error();
            }
            uint64_t value = *(uint64_t *)(bytes + pos);
            switch (len) {
                case 1:
                    value &= 0xff;
                    break;
                case 2:
                    value &= 0xffff;
                    break;
                case 3:
                    value &= 0xffffff;
                    break;
                case 4:
                    value &= 0xffffffff;
                    break;
                case 6:
                    value &= 0xffffffffffff;
                    break;
                case 8:
                    break;
            }
            if (bigendian) value = util::swap(value, len);
            return value;
        }
    };

    std::vector<MemI> inits;

    /* If there is an overlap, it will be overwritten */
    void taintValue(uint64_t start, size_t size) {
        for (size_t i = 0; i < inits.size(); ++i) {  // merge continuous taint memory
            if (inits[i].valid(start)) {
                int offset = start - inits[i].start;
                util::ValueCopy(inits[i].bytes + offset, start, size);
                logger::printline(inits[i].bytes, inits[i].size);
            }
        }
    }

   public:
    int size(uint64_t addr){
        for (size_t i = 0; i < inits.size(); ++i) {
            if (inits[i].valid(addr)) return inits[i].size;
        }
        return -1;
    }
    int offset(uint64_t addr) {
        for (size_t i = 0; i < inits.size(); ++i) {

            if (inits[i].valid(addr)) return addr - inits[i].start;
        }
        return -1;
    }

    bool valid(uint64_t addr) {
        for (size_t i = 0; i < inits.size(); ++i) {
            if (inits[i].valid(addr)) return true;
        }
        return false;
    }

    // use in exit entry function
    void taint(uint64_t start, size_t size) {
        if (size > config::maxsize) {
            size = config::maxsize;
        }
        /* merge continuous taint memory */
        for (size_t i = 0; i < inits.size(); ++i) { 
            if (start == inits[i].begin()) {
                inits[i].size = size;  
                taintValue(start, size);
                return;
            }
            if (start == inits[i].end()) {
                inits[i].size += size;
                taintValue(start, size);
                return;
            }
        }
        //creat & copy
        MemI e = {start, size};
        inits.push_back(e);
        taintValue(start, size);
    }

    uint64_t value(uint64_t addr, size_t size, bool bigendian) {
        if (size > config::maxsize) {
            size = config::maxsize;
        }
        for (size_t i = 0; i < inits.size(); ++i) {
            if (inits[i].valid(addr)) {
                return inits[i].value(addr - inits[i].begin(), size, bigendian);
            }
        }
        return -1;
    }
};

Inits inits;

class Memory {
   public:
    struct MemT {
       private:
        uint64_t src_;
        uint16_t offset_;
        uint8_t size_;
        uint8_t shift_;
        bool bigendian_;
        bool tainted_;

        void set(uint64_t src, size_t size, bool bigendian, uint8_t shift, bool tainted) {
            src_ = src;
            size_ = size;
            offset_ = 0;
            bigendian_ = bigendian;
            shift_ = shift;
            tainted_ = tainted;
        }

        void clear() {
            src_ = 0;
            size_ = 0;
            offset_ = 0;
            shift_ = 0;
            tainted_ = false;
            bigendian_ = false;
        }

       public:
        MemT(): src_(0), offset_(0), size_(0), shift_(0), bigendian_(false), tainted_(false) {}

        void copy(MemT &rhs) {
            tainted_ = rhs.isTainted();
            src_ = rhs.src();
            offset_ = rhs.offset();
            size_ = rhs.size();
            shift_ = rhs.shift();
            bigendian_ = rhs.isBigendian();
        }

        inline bool isTainted() { return tainted_; }

        void taint(uint64_t src, size_t size, bool bigendian, uint8_t shift) {
            set(src, size - 1, bigendian, shift, true);  // mark size
        }

        void untaint() { clear(); }

        inline bool isBigendian() { return bigendian_; }

        inline uint64_t src() { return src_; }

        inline size_t offset() {
            if (offset_ == 0) {
                offset_ = inits.offset(src_);
            }
            return offset_;
        }

        inline size_t size() {
            return size_ + 1;  // mark size
        }

        inline int shift() {
            return shift_;
        }

        inline uint64_t value(size_t s = 0) {
            if (s == 0) s = size();
            if (s > size()) {
            }
            return inits.value(src_, s, bigendian_);
        }

        const char *debug() {
            static char buf[256];
            int n = snprintf(buf, sizeof(buf),
                             "memory  :\t\tsrc: %lx, size: %lx, offset: %lx, "
                             "bigendian: %d, value: %lx\n",
                             src_, size(), offset(), bigendian_, value());
            buf[n] = 0;
            return buf;
        }
    };

    MemT &get(uint64_t addr, bool init = false) {
        if (memories.count(addr) > 0) {
            return memories[addr];
        }
        if (init) {
            // MemT e;
            memories[addr] = MemT();
            return memories[addr];
        }
        return empty;
    }

    bool isTainted(uint64_t addr) {
        return memories.count(addr) > 0 && memories[addr].isTainted();
    }

    // init
    void taint(uint64_t start, size_t size) {
        for (uint64_t addr = start; addr < start + size; ++addr) {
            get(addr, true).taint(addr, 1, false, 0);
        }
    }

    void taint(uint64_t addr, uint64_t src, size_t size, bool bigendian, uint8_t shift) {
        size_t n = 0;
        while (size > n) {
            get(addr + n, true).taint(src + n, size - n, bigendian, shift);
            n += 2;
        }

    }

    void untaint(uint64_t addr) {
        MemT &mem = get(addr);
        size_t size = mem.size();
        size_t n = 0;
        while (size > n) {
            get(addr + n).untaint();
            n += 2;
        }
    }

    uint64_t src(uint64_t addr) { return get(addr).src(); }

    int offset(uint64_t addr) { return get(addr).offset(); }

    size_t size(uint64_t addr) { return get(addr).size(); }

    uint64_t value(uint64_t addr, size_t size = 0) {
        return get(addr).value(size);
    }

    const char *offsets(uint64_t addr) {
        MemT &mem = get(addr);
        return util::nums(mem.offset(), mem.size());
    }

    const char *offsets(uint64_t addr,int size) {
        MemT &mem = get(addr);
        return util::nums(mem.offset(), size);
    }

    const char *debug(uint64_t addr) { return get(addr).debug(); }

   private:
    MemT empty;
    std::map<uint64_t, MemT> memories;
};

Memory mems;


class Register {
   public:
    struct RegT {
       private:
        uint64_t src_;
        int8_t shift_;
        uint8_t size_;
        bool tainted_;
        bool bigendian_;
        uint16_t index_;
        uint16_t offset_;

        void set(uint64_t src, size_t size, bool bigendian, int shift,
                 bool tainted) {
            src_ = src;
            size_ = size;
            bigendian_ = bigendian;
            shift_ = shift;
            tainted_ = tainted;
            offset_ = 0;
        }

        void clear() {
            src_ = 0;
            size_ = 0;
            offset_ = 0;
            tainted_ = false;
            bigendian_ = false;
            shift_ = 0;
        }

        size_t regSize() {
            const static size_t table[5] = {8, 4, 2, 1, 1};
            size_t regsize = table[index_ % 5];
            return regsize;
        }

        const char *name() { return util::regNames[index_]; }

       public:
        RegT() { index_ = 3; };

        RegT(uint16_t index) : index_(index){};

        void copy(RegT &rhs) {
            src_ = rhs.src();
            shift_ = rhs.shift();
            size_ = rhs.size() - 1;  // mark size
            offset_ = 0;
            tainted_ = rhs.isTainted();
            bigendian_ = rhs.isBigendian();
        }

        void taint(uint64_t src, size_t size, bool bigendian, int shift) {
            set(src, size - 1, bigendian, shift, true);  // mark size
        }

        void untaint() { clear(); }

        inline bool isTainted() { return tainted_; }

        inline bool isBigendian() { return bigendian_; }

        void setBigendian(bool b) { bigendian_ = b; }

        inline uint64_t src() {  
            int diff = size_ + 1 - regSize();
            if (diff <= 0) return src_;
            return src_ + diff;
        }

        inline size_t offset() {
            offset_ = inits.offset(src());
            return offset_;
        }

        size_t size() {
            size_t regsize = regSize();
            size_t size = size_ + 1;
            if (regsize < size) {

                return regsize;
            }
            return size;
        }

        uint64_t value(size_t s = 0) {
            if (s == 0) s = size();
            
            uint64_t ret = inits.value(src(), s, bigendian_);
            if (shift_ > 0) {
                ret <<= 8 * shift_;
            } else if (shift_ < 0) {
                ret >>= 8 * shift_;
            }
            return ret;
        }

        size_t index() { return index_; }

        int shift() { return shift_; }

        void setShift(int shift) { shift_ = shift; }

        void lshift(int8_t s) { 
            if (s % 8 != 0) return;
            shift_ += s / 8; 
        }

        void rshift(int8_t s) {
            if (s % 8 != 0) return;
            s /= 8;
            shift_ = std::max(shift_ - s, 0);
            if(size_ == 0){
                return;
            }
            size_ = std::max(size_ - s, 0);
            if (!bigendian_) {
                size_ = std::max(size_ + s, 0);
            }
        }

        const char *debug() {
            static char buf[256];
            int n = snprintf(buf, sizeof(buf),
                             "register %s:\tsrc: %lx, size: %lx, offset: %lx, "
                             "bigendian: %d, value: %lx, shift: %d\n",
                             name(), src(), size(), offset(), bigendian_,
                             value(), shift_);
            buf[n] = 0;
            return buf;
        }
    };

    RegT &get(REG id) {
        if (registers.count(id) > 0) {
            return registers[id];
        }
        RegT e(util::indexOfReg(id)); /* find REG id's 'regs index' */
        registers[id] = e;
        return registers[id];
    }

    bool isTainted(REG id) {

        return registers.count(id) > 0 && registers[id].isTainted();
    }

    void taint(REG id, uint64_t src, size_t size, bool bigendian, int shift) {

        int index = get(id).index();
        index -= index % 5;
        for (int i = 0; i < 5; ++i) {
            id = util::regs[index + i];
            if (id == 0) continue;
            get(id).taint(src, size, bigendian, shift);
        }
    }

    void untaint(REG id) {
        int index = get(id).index() / 5 * 5;
        for (int i = 0; i < 5; ++i) {
            id = util::regs[index + i];
            if (id == 0) continue;
            get(id).untaint();
        }
    }

    uint64_t src(REG id) { return get(id).src(); }

    int offset(REG id) { return get(id).offset(); }

    size_t size(REG id) { return get(id).size(); }

    uint64_t value(REG id, size_t size = 0) { return get(id).value(size); }

    void shift(REG id, int offset) {
        int index = get(id).index() / 5 * 5;
        for (int i = 0; i < 5; ++i) {
            id = util::regs[index + i];
            if (id == 0) continue;
            RegT &reg = get(id);
            
            if (offset >= 0) {
                reg.lshift(offset);
            } else {
                reg.rshift(-offset);
            }
        }
    }

    const char *offsets(REG id) {
        RegT &reg = get(id);

        return util::nums(reg.offset(), reg.size());
    }

    const char *offsets(REG id, int size) {
        RegT &reg = get(id);

        return util::nums(reg.offset(), size);
    }

    const char *debug(REG id) { return get(id).debug(); }

   private:
    RegT empty;
    std::map<REG, RegT> registers;
};

Register regs;

template <typename T1, typename T2>
bool adjacent(T1& lhs, T2& rhs) {
    int lhs_lower = lhs.shift();
    int lhs_upper = lhs.shift() + lhs.size() - 1;
    int rhs_lower = rhs.shift();
    int rhs_upper = rhs.shift() + rhs.size() - 1;
    return (lhs_lower - rhs_upper == 1) || (rhs_lower - lhs_upper == 1);
}

// Wrapper API

bool isTainted(REG reg) { return regs.isTainted(reg); }

bool isTainted(uint64_t addr) { return mems.isTainted(addr); }

int offset(REG reg) { return regs.offset(reg); }

int offset(uint64_t mem) { return mems.offset(mem); }

const char *offsets(REG reg) { return regs.offsets(reg); } 

const char *offsets(REG reg,int size) { return regs.offsets(reg,size); } 

const char *offsets(uint64_t addr) { return mems.offsets(addr); }

const char *offsets(uint64_t addr,int size) { return mems.offsets(addr,size); }

uint64_t value(REG reg, size_t size = 0) { return regs.value(reg, size); }

uint64_t value(uint64_t addr, size_t size = 0) {
    return mems.value(addr, size);
}

const char *debug(REG reg) { return regs.debug(reg); }

const char *debug(uint64_t addr) { return mems.debug(addr); }

uint64_t src(REG reg) { return regs.src(reg); }

uint64_t src(uint64_t addr) { return mems.src(addr); }


size_t size(uint64_t addr) { return inits.size(addr); }

int TaintFlag = 0;

void Init(size_t start, size_t size) {
    if (size > config::maxsize) {
        logger::print("Init size exceed maxsize: %lx\n", size);
        return;
    }
    TaintFlag = 1;
    logger::print("Taint\t(%p, %lx)\n", start, size);
    logger::info("Taint\t(%p, %lx)\n", start, size);


    inits.taint(start, size);

    mems.taint(start, size);
}


void move(REG w, REG r) {
    Register::RegT &reg = regs.get(r);
    regs.taint(w, reg.src(), reg.size(), reg.isBigendian(), reg.shift());
}

int move(REG id, uint64_t addr, size_t size) {
    Memory::MemT &mem = mems.get(addr, true);
    if (!inits.valid(addr)) {
        size = std::min(size, mem.size());
    }
    regs.taint(id, mem.src(), size, mem.isBigendian(), mem.shift());
    return size;
}

void move(uint64_t addr, REG id, size_t size) {
    Register::RegT &reg = regs.get(id);
    mems.taint(addr, reg.src(), std::min(size, reg.size()),
               reg.isBigendian(), reg.shift()); 
}

void move(uint64_t w, uint64_t r, size_t size) {
    Memory::MemT &mem_r = mems.get(r);
    if (!inits.valid(r)) {
        size = std::min(size, mem_r.size());
    }
    mems.taint(w, mem_r.src(), size, mem_r.isBigendian(), mem_r.shift());
}

void remove(uint64_t addr) { mems.untaint(addr); }

void remove(REG id) { regs.untaint(id); }

// add & or
bool merge(REG w, REG r) {
    char buf[1024];
    if (w == r) return false;
    Register::RegT &lhs = regs.get(w);
    Register::RegT &rhs = regs.get(r);
    int diff_shift = lhs.shift() - rhs.shift();
    int diff_src = lhs.src() - rhs.src();
    if (abs(diff_src) > 3 || !adjacent(lhs, rhs)) {
        logger::info("cannot merge\n");
        return false;
    }
    int n = 0;
    n = sprintf(buf + n, "before\n%s%s", debug(w), debug(r));

    uint64_t src = std::min(lhs.src(), rhs.src());
    size_t size = lhs.size() + rhs.size();

    bool bigendian =
        (diff_src > 0 && diff_shift < 0) || (diff_src < 0 && diff_shift > 0);
    int shift = std::min(lhs.shift(), rhs.shift());
    if(lhs.offset() == rhs.offset()){
        return true;
    }
    regs.taint(w, src, size, bigendian, shift);
    n += sprintf(buf + n, "%s", debug(r));
    buf[n] = 0;
    return true;
}


bool merge(REG w, uint64_t r) {
    char buf[1024];
    if (w == r) return false;
    Register::RegT &lhs = regs.get(w);
    Memory::MemT &rhs = mems.get(r);
    int diff_shift = lhs.shift() - rhs.shift();
    int diff_src = lhs.src() - rhs.src();
    if (abs(diff_src) > 3 || !adjacent(lhs, rhs)) {
        return false;
    }
    int n = 0;
    n = sprintf(buf + n, "before\n%s%s", debug(w), debug(r));

    uint64_t src = std::min(lhs.src(), rhs.src());
    size_t size = lhs.size() + rhs.size();
    bool bigendian =
        (diff_src > 0 && diff_shift < 0) || (diff_src < 0 && diff_shift > 0);
    int shift = std::min(lhs.shift(), rhs.shift());

    regs.taint(w, src, size, bigendian, shift);
    n += sprintf(buf + n, "%s", debug(r));
    buf[n] = 0;
    return true;
}


bool merge(uint64_t w, REG r) {
    char buf[1024];
    if (w == r) return false;
    Memory::MemT &lhs = mems.get(w);
    Register::RegT &rhs = regs.get(r);
    int diff_shift = lhs.shift() - rhs.shift();
    int diff_src = lhs.src() - rhs.src();
    if (abs(diff_src) > 3 || !adjacent(lhs, rhs)) {
        return false;
    }
    int n = 0;
    n = sprintf(buf + n, "before\n%s%s", debug(w), debug(r));

    uint64_t src = std::min(lhs.src(), rhs.src());
    size_t size = lhs.size() + rhs.size();
    bool bigendian =
        (diff_src > 0 && diff_shift < 0) || (diff_src < 0 && diff_shift > 0);
    int shift = std::min(lhs.shift(), rhs.shift());

    mems.taint(w, src, size, bigendian, shift);
    n += sprintf(buf + n, "%s", debug(r));
    buf[n] = 0;
    return true;
}


void shift(REG id, int offset) { regs.shift(id, offset); }


void and_(REG id, size_t mask) {  
    Register::RegT &reg = regs.get(id);
    uint64_t src = reg.src();

    bool bigendian = reg.isBigendian();
    // int shift = reg.shift();
    if (mask == 0xff) {
        if (bigendian) src += 3;
        regs.taint(id, src, 1, true, 0);
    } else if (mask == 0xff00) {
        if (bigendian)
            src += 2;
        else
            src += 1;
        regs.taint(id, src, 1, true, 1);
    } else if (mask == 0xff0000) {
        if (bigendian)
            src += 1;
        else
            src += 2;
        regs.taint(id, src, 1, false, 2);
    } else if (mask == 0xff000000) {
        if (!bigendian) src += 3;
        regs.taint(id, src, 1, false, 3);
    } else if (mask == 0xffff) {
        if (bigendian) src += 2;
        regs.taint(id, src, 2, bigendian, 0);
    } else if (mask == 0xffff0000) {
        if (!bigendian) src += 2;
        regs.taint(id, src, 2, bigendian, 2);
    } else {
        logger::info("unhandle mask %lx\n", mask);
    }
}

}  // namespace TaintEngine

#endif

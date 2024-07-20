#ifndef _PIN_OBJECT_H
#define _PIN_OBJECT_H

#include "pin.H"

class Ins {
private:
    INS ins;

public:
    
    Ins(INS ins) {
        this->ins = ins;
    }

    Ins& operator=(INS ins) {
        this->ins = ins;
        return *this;
    }

    operator INS() {
        return ins;
    }
    
    inline ADDRINT Address() {
        return INS_Address(ins);
    }
    
    inline std::string Name() {
        return INS_Disassemble(ins);
    }

    inline OPCODE OpCode() {
        return INS_Opcode(ins);
    }

    inline INT32 Category() {
        return INS_Category(ins);
    }

    inline INT32 Extention() {
        return INS_Extension(ins);
    }

    inline USIZE Size() {
        return INS_Size(ins);
    }

    inline RTN parent() {
        return INS_Rtn(ins);
    }

    inline UINT32 OpCount() {
        return INS_OperandCount(ins);
    }

    // mem
    inline UINT32 MemCount() {
        return INS_MemoryOperandCount(ins);
    }

    inline bool isMemoryRead() {
        return INS_IsMemoryRead(ins);
    }

    inline bool isMemoryWrite() {
        return INS_IsMemoryWrite(ins);
    }

    inline bool isMemOpRead(UINT32 i) {
        return INS_MemoryOperandIsRead(ins, i);
    }

    inline bool isMemOpWrite(UINT32 i) {
        return INS_MemoryOperandIsWritten(ins, i);
    }

    inline USIZE MemRSize() {
        size_t Num = INS_MemoryOperandCount(ins);
        for (size_t i = 0; i < Num; i++) {
            if (INS_MemoryOperandIsRead(ins, i)) {
                return INS_MemoryOperandSize(ins, i);
            }
        }
        return 0;
    }
    
    inline USIZE MemWSize() {
        size_t Num = INS_MemoryOperandCount(ins);
        for (size_t i = 0; i < Num; i++) {
            if (INS_MemoryOperandIsWritten(ins, i)) {
                return INS_MemoryOperandSize(ins, i);
            }
        }
        return 0;
    }

    inline USIZE MemSize(int i) {
        return INS_MemoryOperandSize(ins, i);
    }

    // operand
    inline bool isOpImm(int i) {
        return INS_OperandIsImmediate(ins, i);
    }

    inline UINT64 valueImm(int i){
        return INS_OperandImmediate(ins, i);
    }

    inline bool isOpImplicit(int i) {
        return INS_OperandIsImplicit(ins, i);
    }

    inline bool isOpMem(int i) {
        return INS_OperandIsMemory(ins, i);
    }

    inline bool isOpReg(int i) {
        return INS_OperandIsReg(ins, i);
    }

    inline REG OpReg(int i) {
        return INS_OperandReg(ins, i);
    }

    // Effective Address = Displacement + BaseReg + IndexReg * Scale
    inline ADDRDELTA OpDisplacement(int i) {
        return INS_OperandMemoryDisplacement(ins, i);
    }

    inline REG OpBaseReg(int i) {
        return INS_OperandMemoryBaseReg(ins, i);
    }

    inline REG OpIndexReg(int i) {
        return INS_OperandMemoryIndexReg(ins, i);
    }

    inline UINT32 OpScale(int i) {
        return INS_OperandMemoryScale(ins, i);
    }

    // reg
    inline REG RegR(int i) {
        return INS_RegR(ins, i);
    }

    inline REG RegW(int i) {
        return INS_RegW(ins, i);
    }

    inline bool isMemR2() {
        return INS_HasMemoryRead2(ins);
    }

    // stack and ip
    inline bool isStackRead() {
        return INS_IsStackRead(ins);
    }

    inline bool isStackWrite() {
        return INS_IsStackWrite(ins);
    }

    inline bool isIpRelRead() {
        return INS_IsIpRelRead(ins);
    }

    inline bool isIpRelWrite() {
        return INS_IsIpRelWrite(ins);
    }

    // control
    inline bool isCall() {
        return INS_IsCall(ins);
    }

    inline bool isRet() {
        return INS_IsRet(ins);
    } 

    inline bool isSyscall() {
        return INS_IsSyscall(ins);
    }

    inline bool isSysret() {
        return INS_IsSysret(ins);
    } 

    inline bool isBranch() {
        return INS_IsBranch(ins);
    }

    // specific branch
    inline bool isBranchOrCall() {
        return INS_IsBranch(ins) || INS_IsCall(ins);
        // return INS_IsValidForIpointTakenBranch(ins) || INS_IsControlFlow(ins);
        // return INS_IsBranchOrCall(ins);
    }

    inline bool isDirectBranch() {
        return INS_IsDirectBranch(ins);
    }
 
    inline bool isDirectBranchOrCall() {
        return INS_IsDirectBranch(ins) || INS_IsDirectCall(ins);
        // return INS_IsDirectControlFlow(ins);
        // return INS_IsDirectBranchOrCall(ins);
    }

    inline bool isDirectCall() {
        return INS_IsDirectCall(ins);
    }

    inline bool isIndirectBranchOrCall() {
        // return INS_IsIndirectBranch(ins) || INS_IsIndirectCall(ins);
        return INS_IsIndirectControlFlow(ins);
        // return INS_IsIndirectBranchOrCall(ins);
    }

    // other 
    inline bool isMov() {
        return INS_IsMov(ins);
    }

    inline bool isLea() {
        return INS_IsLea(ins);
    }

    inline bool isSub() {
        return INS_IsSub(ins);
    }

    inline bool isNop() {
        return INS_IsNop(ins);
    }

    inline bool isOriginal() {
        return INS_IsOriginal(ins);
    }

    inline bool isPredicated() {
        return INS_IsPredicated(ins);
    }

    inline bool isPrefetch() {
        return INS_IsPrefetch(ins);
    }

    inline bool isProcedureCall() {
        return INS_IsProcedureCall(ins);
    }

    // iter 
    inline bool Valid() {
        return INS_Valid(ins);
    }

    inline INS Next() {
        return INS_Next(ins);
    }


    std::string Tag(size_t opcount) {
        std::string tag = "";
        for (size_t i = 0; i < opcount; ++i) {
            if (isOpReg(i)) {
                tag += "Reg ";
            }
            if (isOpMem(i)) {
                tag += "Mem ";
            }
            if (isOpImm(i)) {
                tag += "Imm ";
            }
            if (isOpImplicit(i)) {
                tag += "Implicit ";
            }
            if (i < opcount - 1)
                tag += ": ";
        }
        return tag;
    }

    const char *prettify() {
        static char buf[512];
        UINT32 opcount = OpCount();
        OPCODE opcode = OpCode();
        std::string tag = Tag(opcount);
        int n = snprintf(buf, sizeof(buf), "%-16lx%-36sOpCode: %4d \t %s\n", Address(), Name().c_str(), opcode, tag.c_str());
        buf[n] = 0;
        return buf;
    }
};


class Bbl {
private:
    BBL bbl;
public:

    Bbl(BBL bbl) {
        this->bbl = bbl;
    }

    Bbl& operator=(BBL bbl) {
        this->bbl = bbl;
        return *this;
    }

    Ins InsHead() {
        return BBL_InsHead(bbl);
    }

    BBL Next() {
        return BBL_Next(bbl);
    }

    bool Valid() {
        return BBL_Valid(bbl);
    }

    operator BBL() {
        return bbl;
    }

    uint64_t Address() {
        return BBL_Address(bbl);
    }

    size_t Size() {
        return BBL_Size(bbl);
    }
};


class Rtn {

private:
    RTN rtn;

public:
    Rtn(RTN rtn) {
        this->rtn = rtn;
    }

    Rtn& operator=(RTN rtn) {
        this->rtn = rtn;
        return *this;
    }

    operator RTN() {
        return rtn;
    }

    inline void Open() {
        RTN_Open(rtn);
    }

    inline void Close() {
        RTN_Close(rtn);
    }

    inline const std::string& Name() {
        return RTN_Name(rtn);
    }

    inline int Id() {
        return RTN_Id(rtn);
    }

    inline unsigned int Size() {
        return RTN_Size(rtn);
    }

    inline bool isDynamic() {
        return RTN_IsDynamic(rtn);
    }

    inline bool isArtificial() {
        return RTN_IsArtificial(rtn);
    }

    inline std::string getImageName() {
        if (RTN_Valid(rtn)) {
            SEC sec = RTN_Sec(rtn);
            if (SEC_Valid(sec)) {
                IMG img = SEC_Img(sec);
                if (IMG_Valid(img)) {
                    return IMG_Name(img);
                }
            }
        }
        return "";
    }

    // iter
    inline Ins InsHead() {
        return RTN_InsHead(rtn);
    }

    inline Ins InsTail() {
        return RTN_InsTail(rtn);
    }

    // Bbl BblHead() {
    //     return RTN_BblHead(rtn);
    // }

    inline bool Valid() {
        return RTN_Valid(rtn);
    }

    inline RTN Next() {
        return RTN_Next(rtn);
    }
};


class Context {

private:
    const CONTEXT* ctxt;

public:
    Context(const CONTEXT* ctxt) {
        this->ctxt = ctxt;
    }

    inline ADDRINT getReg(REG reg) {
        return PIN_GetContextReg(ctxt, reg);
    }

};

#endif

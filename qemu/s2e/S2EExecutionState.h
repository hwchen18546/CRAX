/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

#ifndef S2E_EXECUTIONSTATE_H
#define S2E_EXECUTIONSTATE_H

#include <klee/ExecutionState.h>
#include <klee/Memory.h>

#include <sys/times.h>

#if defined(__KS_MHHUANG_STATE_FORK__)
#include <list>
#endif

#if defined(__KS_MHHUANG_SYM_READ__)
#include <list>
#include <stack>
#endif

extern "C" {
    struct TranslationBlock;
    struct TimersState;
}

// XXX
struct CPUX86State;
#define CPU_OFFSET(field) offsetof(CPUX86State, field)

//#include <tr1/unordered_map>

namespace s2e {

class Plugin;
class PluginState;
class S2EDeviceState;
struct S2ETranslationBlock;

#ifdef __KS_MHHUANG_STATE_FORK__
struct TerminateInfo {
public:
        TerminateInfo(int i, int p) {eventID = i; eventPara = p;}
    int eventID;
    int eventPara;
};

typedef std::list<TerminateInfo> TerminateInfoList;
typedef std::list<TerminateInfo>::iterator TerminateInfoListIter;
#endif

#ifdef __KS_MHHUANG_SYM_READ__
class S2EExecutionState;
class ValueSet {
protected:
    struct ValueBlock {
        ValueBlock(uint32_t a, uint32_t s) { start = a; size = s; }

        uint32_t start;

        /* The mutable is just a hack to pass compile */
        mutable uint32_t size;

        void setSize(uint32_t s) const { size = s; }
    };

    struct ValueBlockComp {
        bool operator() (const ValueBlock& lhs, const ValueBlock& rhs) const {
            return lhs.start < rhs.start;
        }
    };

    typedef std::set<ValueBlock, ValueBlockComp> BlockSet;
    typedef std::set<ValueBlock, ValueBlockComp>::iterator BlockSetIter;

public:
    class iterator {
        public:
            friend class ValueSet;

            bool operator==(const iterator &rhs);
            bool operator!=(const iterator &rhs);
            iterator& operator=(const iterator &rhs);
            iterator& operator++(int);
            uint32_t operator*();

        private:
            BlockSet *m_pBlockSet;
            BlockSetIter m_it;
            uint32_t m_currentValue;
    };

    ValueSet() { m_size = 0; }
    ValueSet(const ValueSet &v);

    bool isOverlap(uint32_t start, uint32_t end);
    bool containHeadOfConsecutiveBytes(uint32_t start, uint32_t end, uint32_t size);
    bool isAllCovered(uint32_t start, uint32_t end);
    uint32_t size() { return m_size; }
    uint32_t numBlocks();
    void insertInterval(uint32_t start, uint32_t end);
    void removeInterval(uint32_t start, uint32_t end);
    void substract(ValueSet &v);

    /* Use when you know currently no value is bigger than start, the
       speed will be faster than insertInterval */
    void pushBackInterval(uint32_t start, uint32_t end);

    void clear();

    uint32_t front();
    uint32_t back();

    iterator begin();
    iterator end();
    iterator lower_bound(uint32_t key);

    void dumpAllBlocks();
    bool checkSize();

protected:
    BlockSet m_blockSet;
    uint32_t m_size;
};

class ValidAddrSet : public ValueSet {
public:
    ValidAddrSet(S2EExecutionState *state, bool onlySymbolic = false);
    void adjustRange(uint32_t derefSize);
    void adjustSymbolicRange(uint32_t derefSize, ValidAddrSet &validSet);
};

struct SymDeref {
public:
    SymDeref(klee::ref<klee::Expr> a, 
            klee::ref<klee::Expr> v, 
            S2EExecutionState *m, 
            ValidAddrSet *vsa,
            ValidAddrSet *vca);
    ~SymDeref();

    /* Will read memory from metaState, with width equal to valueExpr->getWidth() */
    klee::ref<klee::Expr> readMemory(uint32_t addr);

    /* Return true if some memory cells have address in [startAddr, endAddr] and value in
       valueSet, false otherwise */
    bool containValueInConcreteBlock(uint32_t startAddr, uint32_t endAddr, ValueSet *valueSet);

    klee::ref<klee::Expr> addrExpr;
    klee::ref<klee::Expr> valueExpr;
    S2EExecutionState *metaState;

    /* The address set that contains symbolic value */
    ValidAddrSet *validSymbolicAddrSet;

    /* The address set that contains concrete value */
    ValidAddrSet *validConcreteAddrSet;

    /* The number of states that references it. Ex: a state A read a symbolic address so a
       SymDeref object D is created, then state A forks into state B and C, then both B, C
       reference to D
       If no state reference a SymDeref object, then it should be deleted */
    int refCount;
};

/* This is a extended type of constraint. It means expr must be able to concretize to a value
   in valueSet. If valueSet is NULL, then it's the same as ordinary constraint. */
struct RestrictedVar {
    RestrictedVar() {
        expr = NULL;
        valueSet = NULL;
    }

    RestrictedVar(klee::ref<klee::Expr> e, ValueSet *v = NULL) {
        if(v == NULL) {
            assert(e->getWidth() == klee::Expr::Bool);
        }
        else {
            assert(e->getWidth() == klee::Expr::Int32);
        }

        expr = e;
        valueSet = v;
    }

    /* We don't implement destructor because valueSet is usually be used in other place */

    klee::ref<klee::Expr> expr;
    ValueSet *valueSet;
};

/* This is an evaluator of expression. It determines that whether expr can get a concrete
   value in valueSet under some constraints. */
class RestrictedVarEvaluator {
public:
    /* If valueSet is NULL, then it means a set contains all possible values except 0.
       Note valueSet can not contain 0 since 0 is used to indicate no solution. */
    RestrictedVarEvaluator(const S2EExecutionState *state, klee::TimingSolver *solver) :
        m_state(state),
        m_solver(solver) {
            m_lastValue = 0;
        }

    /* Return a rough set of possible values of expr that can let var.expr fall into
       var.valueSet, and satisfy cons. The number of possible values is at most numLimit. 
       Note the returned set is rough, it may contain some impossible values, but if
       the size of returned set is smaller than numLimit, we can ensure that all possible
       values are included in the returned set. */
    ValueSet getValueSet(klee::ref<klee::Expr> expr, 
            klee::ref<klee::Expr> cons, 
            RestrictedVar var, 
            uint32_t numLimit);

    /* The same as above except that no var restriction. */
    ValueSet getValueSet(klee::ref<klee::Expr> expr,
            klee::ref<klee::Expr> cons,
            uint32_t numLimit);

    /* Return a possible value of var.expr that can let cons become true */
    uint32_t getValue(RestrictedVar var, klee::ref<klee::Expr> cons = NULL);

    /* Return true if precond.expr can fall into precond.valueSet -> postcond.expr can 
       fall into postcond.valueSet. Note this function is only sound, not complete. That
       is, if return true, then the above statement must be true. */
    bool imply(RestrictedVar precond, RestrictedVar postcond);
private:
    uint32_t checkAndGetValue(uint32_t min, uint32_t max);
    uint32_t getValueRecursive(uint32_t min, uint32_t max);

    const S2EExecutionState *m_state;
    klee::TimingSolver *m_solver;
    klee::ref<klee::Expr> m_cons;
    RestrictedVar m_var;

    /* This is used as cache */
    uint32_t m_lastValue;
};

class AsgnSpace {
public:
    class AsgnAxis {
    private:
        struct StartAddr {
            StartAddr(int l, bool s, uint32_t a) {
                level = l;
                isSymbolic = s;
                addr = a;
            }

            int level;
            bool isSymbolic;
            uint32_t addr;
        };

    public:
        friend class AsgnSpace;

        AsgnAxis(SymDeref *d) {
            deref = d;
            startAddrStack.push_back(StartAddr(1, true, d->validSymbolicAddrSet->front()));
            deref->refCount++;
        }

        AsgnAxis(AsgnAxis *axis) {
            deref = axis->deref;
            startAddrStack = axis->startAddrStack;
            deref->refCount++;
        }

        ~AsgnAxis() {
            deref->refCount--;
            if(deref->refCount == 0) {
                delete deref;
            }
        }

        int getLevel();
        void setLevel(int level);

        uint32_t getCurrAddr();
        void setCurrAddr(uint32_t addr);
        uint32_t getMaxAddr();

        bool isOverlap(uint32_t min, uint32_t max);
        bool containValueInAddrRange(uint32_t min, uint32_t max, ValueSet *valueSet);

        klee::ref<klee::Expr> getAddrExpr();
        klee::ref<klee::Expr> getValueExpr();
        klee::ref<klee::Expr> readMemory(uint32_t addr);

        bool isSearchingSymbolic();
        void setSearchingSymbolicFinished();

        void popStartAddr(int level);

        void advanceStartAddr(int level);

    private:
        SymDeref *deref;

        std::list<StartAddr> startAddrStack;
    };

    AsgnSpace() { isFinished = false; }
    AsgnSpace(const AsgnSpace &rhs);

    ~AsgnSpace();

    AsgnSpace& operator=(const AsgnSpace &rhs);

    void addAxis(SymDeref *deref);

    AsgnAxis* currentAxis();

    /* Claim current axis is feasible with current addr, this will cause the next call to 
       currentAxis return next axis */
    void setFeasible();

    /* Claim current axis is infeasible, this will cause backtrace, and select
       other axis to explore */
    void setInfeasible();

    bool startFromLastFeasible();

    bool finished();

    klee::ref<klee::Expr> currentConstraint();

    uint32_t numAxises();

    void dumpAllAxises();

private:
    struct AsgnSubspace {
        AsgnSubspace(std::list<AsgnAxis*>::iterator it,
                klee::ref<klee::Expr> cons,
                int l) {
            axisListIter = it;
            constraint = cons;
            level = l;
        }

        /* This iterator can iterate all axises that are free in this subspace, in fact, 
           it's an iterator of axisList. And the axis pointed by this iterator is the 
           axis that are going to be evaluated */
        std::list<AsgnAxis*>::iterator axisListIter;
        std::list<AsgnAxis*> updatedAxises;

        /* Assignment that in the sub space must satisfy this constraint. In fact, this
           is from the axis assignment of its super-spaces */
        klee::ref<klee::Expr> constraint;

        int level;
    };

    void copyContent(const AsgnSpace &rhs);

    std::list<AsgnAxis*> axisList;

    /* This is used to search feasible assignments, each element is a sub-space of its
       buttom element */
    std::list<AsgnSubspace*> subspaceStack;

    bool isFinished;
    bool hasAssignment;
};

class AsgnSpaceSearcher {
public:
    AsgnSpaceSearcher(const S2EExecutionState *st, klee::TimingSolver *so) :
        state(st),
        solver(so) { 
        concreteSearchTimeout = 86400;
    }

    /* Search the remaining portion of space, and find the first point that can let var
       become a valid value. And fill the point to space, the next search will start from
       that point */
    uint32_t fillSpaceAndGetValue(AsgnSpace *space, RestrictedVar var);

    void setConcreteSearchTimeout(float t) {
        concreteSearchTimeout = t;
    }

private:
    class AsgnAxisSearcher {
    public:
        AsgnAxisSearcher(const S2EExecutionState *st, klee::TimingSolver *so) :
            state(st),
            solver(so),
            evaluator(st, so) {
            concreteSearchTimeout = 86400;
        }

        void setConcreteSearchTimeout(float t) {
            concreteSearchTimeout = t;
        }

        /* Find the assignment with smallest address such that v can be a valid value, and c
           can be true, and fill it into a.
           Return a possible concrete value of v */
        uint32_t fillAxisAndGetValue(AsgnSpace::AsgnAxis *a, RestrictedVar v, klee::ref<klee::Expr> c = NULL);
    private:
        uint32_t fillAxisAndGetValueAux();
        /* Find the assignment with smallest address that matchs the constraint specified by 
           tempCons and tempAddrSet, state->constraints, and with address range [min, max]. If 
           such assignment exists, fill it into tempAsgn and return true, otherwise return false. */
        uint32_t fillAxisAndGetValueRecursive(uint32_t min, uint32_t max);

        const S2EExecutionState *state;
        klee::TimingSolver *solver;

        /* Timeout in seconds*/
        float concreteSearchTimeout;

        /* Just a temp variable to record the searching start time */
        clock_t concreteSearchStartTime;

        AsgnSpace::AsgnAxis *axis;
        RestrictedVar var;
        klee::ref<klee::Expr> cons;
        ValueSet *possibleValueSet;
        RestrictedVarEvaluator evaluator;
    };

    const S2EExecutionState *state;
    klee::TimingSolver *solver;

    float concreteSearchTimeout;
};
#endif  // __KS_MHHUANG_SYM_READ__

//typedef std::tr1::unordered_map<const Plugin*, PluginState*> PluginStateMap;
typedef std::map<const Plugin*, PluginState*> PluginStateMap;
typedef PluginState* (*PluginStateFactory)(Plugin *p, S2EExecutionState *s);

class S2EExecutionState : public klee::ExecutionState
{
protected:
    friend class S2EExecutor;

    static int s_lastStateID;

#ifdef __KS_MHHUANG_STATE_FORK__
    S2EExecutionState *m_parentState, *m_childState;
    int m_waitReturnValue;
    TerminateInfoList m_terminateInfoList;
#endif

    /** Unique numeric ID for the state */
    int m_stateID;

    PluginStateMap m_PluginState;

    bool m_symbexEnabled;

    /* Internal variable - set to PC where execution should be
       switched to symbolic (e.g., due to access to symbolic memory */
    uint64_t m_startSymbexAtPC;

    /** Set to true when the state is active (i.e., currently selected).
        NOTE: for active states, SharedConcrete memory objects are stored
              in shared locations, for inactive - in ObjectStates. */
    bool m_active;

    /** Set to true when the state executes code in concrete mode.
        NOTE: When m_runningConcrete is true, CPU registers that contain
              concrete values are stored in the shared region (env global
              variable), all other CPU registers are stored in ObjectState.
    */
    bool m_runningConcrete;

    /* Move the following to S2EExecutor */
    klee::MemoryObject* m_cpuRegistersState;
    klee::MemoryObject* m_cpuSystemState;

    klee::ObjectState *m_cpuRegistersObject;
    klee::ObjectState *m_cpuSystemObject;

    klee::MemoryObject* m_dirtyMask;

    S2EDeviceState *m_deviceState;

    /* The following structure is used to store QEMU time accounting
       variables while the state is inactive */
    TimersState* m_timersState;
    int64_t m_qemuIcount;

    S2ETranslationBlock* m_lastS2ETb;

    uint64_t m_lastMergeICount;

    bool m_needFinalizeTBExec;

    ExecutionState* clone();
    void addressSpaceChange(const klee::MemoryObject *mo,
                            const klee::ObjectState *oldState,
                            klee::ObjectState *newState);
public:
    clock_t start, middle, end;
    struct tms t_start, t_middle, t_end;

#ifdef __KS_MHHUANG_SYM_READ__
    friend class SymDeref;
    friend class ValidAddrSet;
    
    mutable AsgnSpace m_asgnSpace;
    mutable bool m_needUpdateAsgnSpace;

    void addSymDeref(SymDeref *deref);
    uint32_t getValue(klee::TimingSolver &solver, RestrictedVar var);
    void updateAsgnSpace(klee::TimingSolver &solver) const;
#endif

    virtual bool evaluate(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, klee::Solver::Validity &result) const;
    virtual bool mustBeTrue(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, bool &result) const;
    virtual bool mustBeFalse(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, bool &result) const;
    virtual bool mayBeTrue(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, bool &result) const;
    virtual bool mayBeFalse(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, bool &result) const;
    virtual bool getValue(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, klee::ref<klee::ConstantExpr> &result) const;
    virtual bool getInitialValues(klee::TimingSolver &solver, const std::vector<const klee::Array*> &objects, 
            std::vector< std::vector<unsigned char> > &result) const;

    /* An ugly hack to let Executor::getSymbolicSolution to work */
    virtual ExecutionState* getClone() const;
    bool m_isHack;

    /* A wrapper function that handles the work needed for DISCARD_KERNEL and REMOVE_ADD_CONSTRAINT
       options. This function is used to add path constraint, don't use it to add temporarily 
       constraint such as exploit gen usage. */
    virtual void addConstraint(klee::ref<klee::Expr> e) const;

    void addTempConstraint(klee::ref<klee::Expr> e) const;
    void clearTempConstraints() const;
    std::vector<klee::ref<klee::Expr> > getTempConstraints() const;
    void setTempConstraints(std::vector<klee::ref<klee::Expr> > tempCons) const;
    void addPermanentConstraintAndClearTempConstraints(klee::ref<klee::Expr> e) const;

    std::vector<uint64_t> concrete_byte;
    //std::vector<std::pair<uint64_t, klee::ref<klee::Expr> > > concrete_byte;
public:
    enum AddressType {
        VirtualAddress, PhysicalAddress, HostAddress
    };

    S2EExecutionState(klee::KFunction *kf);
    ~S2EExecutionState();

    int getID() const { return m_stateID; }

    S2EDeviceState *getDeviceState() const {
        return m_deviceState;
    }

#ifdef __KS_MHHUANG_STATE_FORK__
    void addTerminateInfo(int eventID, int eventPara) {
        m_terminateInfoList.push_back(TerminateInfo(eventID, eventPara));
    }
#endif

    TranslationBlock *getTb() const;

    uint64_t getTotalInstructionCount();

    /*************************************************/

    PluginState* getPluginState(Plugin *plugin, PluginStateFactory factory) {
        PluginStateMap::iterator it = m_PluginState.find(plugin);
        if (it == m_PluginState.end()) {
            PluginState *ret = factory(plugin, this);
            assert(ret);
            m_PluginState[plugin] = ret;
            return ret;
        }
        return (*it).second;
    }

    /** Returns true is this is the active state */
    bool isActive() const { return m_active; }

    /** Returns true if this state is currently running in concrete mode */
    bool isRunningConcrete() const { return m_runningConcrete; }

    /** Returns a mask of registers that contains symbolic values */
    uint64_t getSymbolicRegistersMask() const;

    klee::ref<klee::Expr> getEax();

    /** Read CPU general purpose register */
    klee::ref<klee::Expr> readCpuRegister(unsigned offset,
                                          klee::Expr::Width width) const;

    /** Write CPU general purpose register */
    void writeCpuRegister(unsigned offset, klee::ref<klee::Expr> value);

    /** Read concrete value from general purpose CPU register */
    bool readCpuRegisterConcrete(unsigned offset, void* buf, unsigned size);

    /** Write concrete value to general purpose CPU register */
    void writeCpuRegisterConcrete(unsigned offset, const void* buf, unsigned size);

    /** Read CPU system state */
    uint64_t readCpuState(unsigned offset, unsigned width) const;

    /** Write CPU system state */
    void writeCpuState(unsigned offset, uint64_t value, unsigned width);

    uint64_t getPc() const;
    uint64_t getPid() const;
    uint64_t getSp() const;
    uint64_t getBp() const;
    uint64_t getAx() const;

    void setPc(uint64_t pc);
    void setSp(uint64_t sp);

    bool getReturnAddress(uint64_t *retAddr);
    bool bypassFunction(unsigned paramCount);
    void undoCallAndJumpToSymbolic();

    void dumpStack(unsigned count);
    void dumpStack(unsigned count, uint64_t sp);

    bool isForkingEnabled() const { return !forkDisabled; }
    void setForking(bool enable) {
        forkDisabled = !enable;
    }

    void enableForking();
    void disableForking();


    bool isSymbolicExecutionEnabled() const {
        return m_symbexEnabled;
    }

    void enableSymbolicExecution();
    void disableSymbolicExecution();

    /** Read value from memory, returning false if the value is symbolic */
    bool readMemoryConcrete(uint64_t address, void *buf, uint64_t size,
                            AddressType addressType = VirtualAddress);

    /** Write concrete value to memory */
    bool writeMemoryConcrete(uint64_t address, void *buf,
                             uint64_t size, AddressType addressType=VirtualAddress);

    /** Read an ASCIIZ string from memory */
    bool readString(uint64_t address, std::string &s, unsigned maxLen=256);
    bool readUnicodeString(uint64_t address, std::string &s, unsigned maxLen=256);

    /** Virtual address translation (debug mode). Returns -1 on failure. */
    uint64_t getPhysicalAddress(uint64_t virtualAddress) const;

    /** Address translation (debug mode). Returns host address or -1 on failure */
    uint64_t getHostAddress(uint64_t address,
                            AddressType addressType = VirtualAddress) const;

    /** Access to state's memory. Address is virtual or physical,
        depending on 'physical' argument. Returns NULL or false in
        case of failure (can't resolve virtual address or physical
        address is invalid) */
    klee::ref<klee::Expr> readMemory(uint64_t address,
                             klee::Expr::Width width,
                             AddressType addressType = VirtualAddress) const;
    klee::ref<klee::Expr> readMemory8(uint64_t address,
                              AddressType addressType = VirtualAddress) const;

    bool writeMemory(uint64_t address,
                     klee::ref<klee::Expr> value,
                     AddressType addressType = VirtualAddress);
    bool writeMemory(uint64_t address,
                     uint8_t* buf,
                     klee::Expr::Width width,
                     AddressType addressType = VirtualAddress);

    bool writeMemory8(uint64_t address,
                      klee::ref<klee::Expr> value,
                      AddressType addressType = VirtualAddress);
    bool writeMemory8 (uint64_t address, uint8_t  value,
                       AddressType addressType = VirtualAddress);
    bool writeMemory16(uint64_t address, uint16_t value,
                       AddressType addressType = VirtualAddress);
    bool writeMemory32(uint64_t address, uint32_t value,
                       AddressType addressType = VirtualAddress);
    bool writeMemory64(uint64_t address, uint64_t value,
                       AddressType addressType = VirtualAddress);

    CPUX86State *getConcreteCpuState() const;

    /** Creates new unconstrained symbolic value */
    klee::ref<klee::Expr> createSymbolicValue(klee::Expr::Width width,
                              const std::string& name = std::string());

    std::vector<klee::ref<klee::Expr> > createSymbolicArray(
            unsigned size, const std::string& name = std::string());

    /** Debug functions **/
    void dumpX86State(std::ostream &os) const;

#ifdef __MHHUANG_MEASURE_TIME__
    void printAllStat();
#endif

    /** Attempt to merge two states */
    bool merge(const ExecutionState &b);
};

//Some convenience macros
#define SREAD(state, addr, val) if (!state->readMemoryConcrete(addr, &val, sizeof(val))) { return; }
#define SREADR(state, addr, val) if (!state->readMemoryConcrete(addr, &val, sizeof(val))) { return false; }

}

#endif // S2E_EXECUTIONSTATE_H

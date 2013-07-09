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

extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "sysemu.h"

#include "tcg-llvm.h"
#include "cpu.h"

extern struct CPUX86State *env;
}

#include "S2EExecutionState.h"
#include <s2e/s2e_config.h>
#include <s2e/S2EDeviceState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugin.h>

#include <klee/Context.h>
#include <klee/Memory.h>
#include <s2e/S2E.h>
#include <s2e/s2e_qemu.h>

#include <llvm/Support/CommandLine.h>

#include <iomanip>

//#define S2E_ENABLEMEM_CACHE

namespace klee {
extern llvm::cl::opt<bool> DebugLogStateMerge;
}

namespace {
CPUTLBEntry s_cputlb_empty_entry = { -1, -1, -1, -1 };
}

namespace s2e {

using namespace klee;

int S2EExecutionState::s_lastStateID = 0;

#ifdef __KS_MHHUANG_SYM_READ__
static klee::ref<klee::Expr> getBoundConstraint(
        klee::ref<klee::Expr> expr, uint32_t min, uint32_t max) {
    if(min == max) {
        klee::ref<klee::Expr> rangeBound = klee::EqExpr::create(expr, 
                klee::ConstantExpr::create(min, klee::Expr::Int32));
        return rangeBound;
    }
    else {
        klee::ref<klee::Expr> upperBound = klee::UleExpr::create(expr, 
                klee::ConstantExpr::create(max, klee::Expr::Int32));
        klee::ref<klee::Expr> lowerBound = klee::UgeExpr::create(expr,
                klee::ConstantExpr::create(min, klee::Expr::Int32));
        klee::ref<klee::Expr> rangeBound = klee::AndExpr::create(upperBound, lowerBound);
        return rangeBound;
    }
}

ValueSet::ValueSet(const ValueSet &v) {
    m_size = v.m_size;
    m_blockSet = v.m_blockSet;
}

/* Determines whether the interval [start, end] contains some value in this ValueSet */
bool ValueSet::isOverlap(uint32_t start, uint32_t end) {
    assert(start<=end && "Misuse of isOverlap()");

    BlockSetIter it = m_blockSet.upper_bound(ValueBlock(start, 1));
    if(it != m_blockSet.begin())
        it--;
    while(it != m_blockSet.end() && it->start <= end) {
        uint32_t currStart = it->start;
        uint32_t currEnd = it->start+it->size-1;

        if(currStart < start) {
            if(currEnd >= start) {
                return true;
            }
        }
        else {
            return true;
        }

        it++;
    }

    return false;
}

/* Determines whether there is any value A in [start, end], where the values
   A, A+1, ... , A+size-1, are all in this ValueSet */
bool ValueSet::containHeadOfConsecutiveBytes(uint32_t start, uint32_t end, uint32_t size) {
    BlockSetIter it = m_blockSet.upper_bound(ValueBlock(start, 1));
    if(it != m_blockSet.begin())
        it--;
    while(it != m_blockSet.end() && it->start<=end) {
        uint32_t currStart = it->start;
        uint32_t currEnd = it->start+it->size-1;

        if(currStart < start) {
            if(currEnd >= start && currEnd-start+1 >= size) {
                return true;
            }
        }
        else {
            if(currStart <= end && currEnd-currStart+1 >= size) {
                return true;
            }
        }

        it++;
    }

    return false;
}

/* Return true if all values in range [start, end] are in this ValueSet */
bool ValueSet::isAllCovered(uint32_t start, uint32_t end) {
    BlockSetIter it = m_blockSet.upper_bound(ValueBlock(start, 1));
    if(it != m_blockSet.begin())
        it--;
    
    uint32_t currStart = it->start;
    uint32_t currEnd = it->start+it->size-1;

    if(currStart <= start && currEnd >= end) {
        return true;
    }

    return false;
}

uint32_t ValueSet::numBlocks() {
    return m_blockSet.size();
}

void ValueSet::insertInterval(uint32_t start, uint32_t end) {
    BlockSetIter it = m_blockSet.upper_bound(ValueBlock(start, 1));
    if(it != m_blockSet.begin())
        it--;
    /* In order to merge adjanct blocks, we use the bound end+1 */
    while(it != m_blockSet.end() && (it->start <= end+1 || end == 0xffffffff)) {
        BlockSetIter it2 = it;
        it++;

        uint32_t currStart = it2->start;
        uint32_t currEnd = it2->start+it2->size-1;

        if(currStart < start) {
            /* In order to merge adjanct blocks, we use the bound start-1
               We don't need to worry that start-1 will cause overflow, since the 
               currStart < start condition ensures start > 0 */
            if(currEnd >= start-1) {
                start = currStart;

                m_size = m_size-it2->size;
                m_blockSet.erase(it2);
            }
        }
        else {
            if(currEnd > end) {
                end = currEnd;
            }

            m_size = m_size-it2->size;
            m_blockSet.erase(it2);
        }
    }

    ValueBlock block(start, end-start+1);
    m_blockSet.insert(block);
    m_size = m_size+(end-start+1);
}

void ValueSet::removeInterval(uint32_t start, uint32_t end) {
    uint32_t deletedStart = start;
    uint32_t deletedEnd = end;

    BlockSetIter it = m_blockSet.upper_bound(ValueBlock(start, 1));
    if(it != m_blockSet.begin())
        it--;
    while(it != m_blockSet.end() && it->start <= end) {
        bool needDelete = true;

        BlockSetIter it2 = it;
        it++;

        uint32_t currStart = it2->start;
        uint32_t currEnd = it2->start+it2->size-1;

        if(currStart < start) {
            if(currEnd >= start) {
                deletedStart = currStart;
            }
            else {
                needDelete = false;
            }
        }

        if(currEnd > end) {
            deletedEnd = currEnd;
        }

        if(needDelete) {
            m_size = m_size-it2->size;
            m_blockSet.erase(it2);
        }
    }

    if(deletedStart < start) {
        m_blockSet.insert(ValueBlock(deletedStart, start-deletedStart));
        m_size = m_size+(start-deletedStart);
    }

    if(deletedEnd > end) {
        m_blockSet.insert(ValueBlock(end+1, deletedEnd-end));
        m_size = m_size+(deletedEnd-end);
    }
}

void ValueSet::substract(ValueSet &v) {
    /* The simplest way, we can use more optimation */
    BlockSetIter it;
    for(it=v.m_blockSet.begin(); it!=v.m_blockSet.end(); it++) {
        removeInterval(it->start, it->start+it->size-1);
    }
}

void ValueSet::pushBackInterval(uint32_t start, uint32_t end) {
    m_size = m_size+(end-start+1);

    if(m_blockSet.empty()) {
        m_blockSet.insert(ValueBlock(start, end-start+1));
        return;
    }

    BlockSetIter it = m_blockSet.end();
    it--;

    assert(it->start+it->size <= start);

    if(it->start+it->size == start) {
        it->size = it->size+(end-start+1);
    }
    else {
        m_blockSet.insert(it, ValueBlock(start, end-start+1));
    }
}

void ValueSet::clear() {
    m_blockSet.clear();
    m_size = 0;
}

uint32_t ValueSet::front() {
    if(m_size == 0) {
        return 0;
    }

    assert(!m_blockSet.empty());

    BlockSetIter it = m_blockSet.begin();
    return it->start;
}

uint32_t ValueSet::back() {
    if(m_size == 0) {
        return 0;
    }

    assert(!m_blockSet.empty());

    BlockSetIter it = m_blockSet.end();
    it--;
    return it->start+it->size-1;
}

ValueSet::iterator ValueSet::begin() {
    iterator it;
    it.m_pBlockSet = &m_blockSet;
    it.m_it = m_blockSet.begin();
    if(it.m_it != m_blockSet.end()) {
        it.m_currentValue = it.m_it->start;
    }
    else {
        it.m_currentValue = 0;
    }

    return it;
}

ValueSet::iterator ValueSet::end() {
    iterator it;
    it.m_pBlockSet = &m_blockSet;
    it.m_it = m_blockSet.end();
    it.m_currentValue = 0;

    return it;
}

ValueSet::iterator ValueSet::lower_bound(uint32_t key) {
    iterator it;
    it.m_pBlockSet = &m_blockSet;

    it.m_it = m_blockSet.upper_bound(ValueBlock(key, 1));
    if(it.m_it != m_blockSet.begin())
        it.m_it--;
    while(it.m_it != m_blockSet.end() && it.m_it->start <= key) {
        uint32_t currStart = it.m_it->start;
        uint32_t currEnd = it.m_it->start+it.m_it->size-1;

        if(currStart < key) {
            if(currEnd >= key) {
                it.m_currentValue = key;
                return it;
            }
        }
        else {
            it.m_currentValue = key;
            return it;
        }

        it.m_it++;
    }

    return end();
}

bool ValueSet::iterator::operator==(const ValueSet::iterator &rhs) {
    return m_it == rhs.m_it &&
        m_currentValue == rhs.m_currentValue &&
        m_pBlockSet == rhs.m_pBlockSet;
}

bool ValueSet::iterator::operator!=(const ValueSet::iterator &rhs) {
    return m_it != rhs.m_it ||
        m_currentValue != rhs.m_currentValue ||
        m_pBlockSet != rhs.m_pBlockSet;
}

ValueSet::iterator& ValueSet::iterator::operator=(const ValueSet::iterator &rhs) {
    /* We don't need to implement copy constructor since the default copy
       constructor also do the same thing */
    m_it = rhs.m_it;
    m_currentValue = rhs.m_currentValue;
    m_pBlockSet = rhs.m_pBlockSet;

    return *this;
}

ValueSet::iterator& ValueSet::iterator::operator++(int) {
    if(m_it != m_pBlockSet->end()) {
        if(m_currentValue == m_it->start+m_it->size-1) {
            m_it++;
            if(m_it != m_pBlockSet->end()) {
                m_currentValue = m_it->start;
            }
            else {
                m_currentValue = 0;
            }
        }
        else {
            m_currentValue++;
        }
    }

    return *this;
}

uint32_t ValueSet::iterator::operator*() {
    return m_currentValue;
}

void ValueSet::dumpAllBlocks() {
    BlockSetIter it;
    for(it=m_blockSet.begin(); it!=m_blockSet.end(); it++) {
        std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << it->start <<
            " - 0x" << std::setw(8) << std::setfill('0') << it->start+it->size-1 << std::endl;
    }
}

bool ValueSet::checkSize() {
    int size = 0;
    BlockSetIter it;
    for(it=m_blockSet.begin(); it!=m_blockSet.end(); it++) {
        size = size+it->size;
    }

    if(size == m_size) {
        return true;
    }
    else {
        return false;
    }
}

ValidAddrSet::ValidAddrSet(S2EExecutionState *state, bool onlySymbolic) {
    m_size = 0;

    bool activated = false;
    if(state->m_active == false) {
        state->m_active = true;
        activated = true;
    }

    uint64_t addr = 0;
    while(addr<=0xffffffff) {
        uint64_t pageStart = (addr & TARGET_PAGE_MASK);
        uint64_t hostAddress = state->getHostAddress(addr);
        if(hostAddress != (uint64_t)-1) {
            if(!onlySymbolic) {
                pushBackInterval(pageStart, pageStart+TARGET_PAGE_SIZE-1);
                addr = pageStart + TARGET_PAGE_SIZE;
            }
            else {
                uint64_t objectStart = (addr & S2E_RAM_OBJECT_MASK);
                klee::ObjectPair op = state->addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);
                if(!op.second->isAllConcrete()) {
                    uint64_t objectOffset = 0;
                    uint64_t objectSize = op.second->size;

                    for(; objectOffset<objectSize; objectOffset++) {
                        if(op.second->isByteKnownSymbolic(objectOffset) && 
                                !isa<klee::ConstantExpr>(op.second->read8(objectOffset))) {
                            pushBackInterval(objectStart+objectOffset, objectStart+objectOffset);
                        }
                    }
                }

                addr = objectStart + S2E_RAM_OBJECT_SIZE;
            }
        }
        else {
            addr = pageStart + TARGET_PAGE_SIZE;
        }
    }

    if(activated)
        state->m_active = false;
}

void ValidAddrSet::adjustRange(uint32_t derefSize) {
    BlockSetIter it;
    for(it=m_blockSet.begin(); it!=m_blockSet.end();) {
        if(it->size < derefSize) {
            BlockSetIter it2 = it;
            it++;

            m_size = m_size-it2->size;
            m_blockSet.erase(it2);
        }
        else {
            it->setSize(it->size-derefSize+1);
            m_size = m_size-derefSize+1;

            it++;
        }
    }
}

/* The original ValidAddrSet only contains the addresses that contains symbolic bytes,
   now we need to adjust with the read size, ex: if the read size is 4 bytes

    |********|      => Valid address set for 4 byte read
        |******|    => Address that contains symbolic byte

     |*******|      => Valid address set for 4 byte read, and the value read out is symbolic

   The validSet parameter is the Valid address set for 4 byte read, as illustrated. */
void ValidAddrSet::adjustSymbolicRange(uint32_t derefSize, ValidAddrSet &validSet) {
    BlockSet blockSet = m_blockSet;

    BlockSetIter it;
    for(it=blockSet.begin(); it!=blockSet.end(); it++) {
        uint32_t currStart = it->start;
        uint32_t currEnd = it->start+it->size-1;

        /* To avoid overflow, since address can't have the value below 0x4, this won't be
           a problem */
        assert(currStart >= derefSize);

        for(int i=0; i<derefSize-1 && currEnd-i>=currStart; i++) {
            if(!validSet.isOverlap(currEnd-i, currEnd-i)) {
                removeInterval(currEnd-i, currEnd-i);
            }
        }

        for(int i=1; i<derefSize; i++) {
            if(validSet.isOverlap(currStart-i, currStart-i)) {
                insertInterval(currStart-i, currStart-i);
            }
        }
    }
}

SymDeref::SymDeref(klee::ref<klee::Expr> a, 
        klee::ref<klee::Expr> v, 
        S2EExecutionState *m, 
        ValidAddrSet *vsa,
        ValidAddrSet *vca) {
    addrExpr = a;
    valueExpr = v;
    metaState = m;
    validSymbolicAddrSet = vsa;
    validConcreteAddrSet = vca;
    refCount = 0;
}

SymDeref::~SymDeref() {
    delete metaState;
    delete validSymbolicAddrSet;
    delete validConcreteAddrSet;
}

klee::ref<klee::Expr> SymDeref::readMemory(uint32_t addr) {
    assert(metaState != NULL);

    /* A hack to avoid assertion fail */
    metaState->m_active = true;

    klee::ref<klee::Expr> res = metaState->readMemory(addr, valueExpr->getWidth());

    metaState->m_active = false;

    return res;
}

bool SymDeref::containValueInConcreteBlock(uint32_t startAddr, uint32_t endAddr, ValueSet *valueSet) {
    ValueSet::iterator it = validConcreteAddrSet->lower_bound(startAddr);

    while(it!=validConcreteAddrSet->end() && (*it) <= endAddr) {
        klee::ref<klee::Expr> ve = readMemory(*it);
        klee::ref<klee::ConstantExpr> vce = dyn_cast<klee::ConstantExpr>(ve);

        assert(!vce.isNull());

        uint32_t v = vce->getZExtValue();
        if(valueSet->isOverlap(v, v)) {
            return true;
        }

        it++;
    }

    return false;
}

/* Before calling this, must ensure that cons can be satisfied, and var can be a valid value
   subject to state->constraints */
ValueSet RestrictedVarEvaluator::getValueSet(
        klee::ref<klee::Expr> expr,
        klee::ref<klee::Expr> cons,
        RestrictedVar var,
        uint32_t numLimit) {
    std::vector<klee::ref<klee::Expr> > tempConstraints = m_state->constraints.getTempConstraints();

    ValueSet valueSet;

    /* The addTempConstraint call will make ConstraintManager to be readyToUse, so it must
       work. But we still need a more simple architecture */
    m_state->constraints.addTempConstraint(cons);
    if(var.expr.isNull()==false && var.expr->getWidth()==klee::Expr::Bool) {
        m_state->constraints.addTempConstraint(var.expr);
    }

    while(valueSet.size() < numLimit) {
        klee::ref<klee::ConstantExpr> valueCE;
        assert(m_solver->oGetValue(*m_state, expr, valueCE));

        uint32_t value = valueCE->getZExtValue();
        valueSet.insertInterval(value, value);

        /* Test whether expr can be other value */
        klee::ref<klee::Expr> notEqual = klee::Expr::createIsZero(
                klee::EqExpr::create(expr, valueCE));
        bool res;
        assert(m_solver->oMayBeTrue(*m_state, notEqual, res));
        if(res) {
            m_state->constraints.addTempConstraint(notEqual);
        }
        else {
            break;
        }
    }

    m_state->constraints.setTempConstraints(tempConstraints);
    return valueSet;
}

/* Before calling this, must ensure that cons can be satisfied subject to state->constraints */
ValueSet RestrictedVarEvaluator::getValueSet(
        klee::ref<klee::Expr> expr,
        klee::ref<klee::Expr> cons,
        uint32_t numLimit) {
    return getValueSet(expr, cons, RestrictedVar(), numLimit);
}

#define NUM_VALUE_TRIAL 5
uint32_t RestrictedVarEvaluator::getValue(
        RestrictedVar var,
        klee::ref<klee::Expr> cons) {
    if(cons.isNull()) {
        m_cons = klee::ConstantExpr::create(1, klee::Expr::Bool);
    }
    else {
        m_cons = cons;
    }

    m_var = var;

    if(m_var.expr->getWidth() == klee::Expr::Bool) {
        klee::ref<klee::Expr> totalCons = klee::AndExpr::create(
                m_var.expr,
                m_cons);
        bool res;
        assert(m_solver->oMayBeTrue(*m_state, totalCons, res));
        if (res)
            return 1;
        return 0;
    }
    else {
        /* First check if the cached value works, this is because the var parameter of
           consecutive query are usually the same, just check the previous result. */
        if(m_lastValue != 0 && m_var.valueSet->isOverlap(m_lastValue, m_lastValue)) {
            klee::ref<klee::Expr> equal = klee::EqExpr::create(m_var.expr, 
                    klee::ConstantExpr::create(m_lastValue, m_var.expr->getWidth()));
            klee::ref<klee::Expr> totalCons = klee::AndExpr::create(equal, m_cons);

            bool res;
            assert(m_solver->oMayBeTrue(*m_state, totalCons, res));
            if(res) {
                return m_lastValue;
            }
        }

        bool res;
        assert(m_solver->oMayBeTrue(*m_state, m_cons, res));
        if(!res) {
            return 0;
        }

        /* Find a sample of values, fast check if they are valid */
        ValueSet possibleValue = getValueSet(m_var.expr, m_cons, NUM_VALUE_TRIAL);

        /* Because this function don't need to find the smallest valid value, we can
           fast check whether these possible value are valid */
        ValueSet::iterator it;
        for(it=possibleValue.begin(); it!=possibleValue.end(); it++) {
            uint32_t m_lastValue = *it;
            if(m_var.valueSet->isOverlap(m_lastValue, m_lastValue)) {
                return m_lastValue;
            }
        }

        /* May have more possible values */
        if(possibleValue.size() == NUM_VALUE_TRIAL) {
            uint32_t startValue = 0;
            uint32_t endValue = 0;

            it = possibleValue.begin();
            if(*it == 0) {
                /* We don't consider the case that possible value is 0 */
                startValue = 1;
                it++;
            }
            for(; it!=possibleValue.end(); it++) {
                endValue = (*it)-1;

                if(startValue <= endValue) {
                    m_lastValue = checkAndGetValue(startValue, endValue);
                    if(m_lastValue != 0) {
                        return m_lastValue;
                    }
                }

                startValue = (*it)+1;
            }
            if(startValue != 0) {
                m_lastValue = checkAndGetValue(startValue, 0xffffffff);
                if(m_lastValue != 0) {
                    return m_lastValue;
                }
            }
        }

        return 0;
    }
}

uint32_t RestrictedVarEvaluator::checkAndGetValue(uint32_t min, uint32_t max) {
    if(m_var.valueSet->isOverlap(min, max) == false) {
        return 0;
    }
        
    klee::ref<klee::Expr> rangeBound = getBoundConstraint(m_var.expr, min, max);
    klee::ref<klee::Expr> totalCons = klee::AndExpr::create(m_cons, rangeBound);

    bool res;
    assert(m_solver->oMayBeTrue(*m_state, totalCons, res));
    if(!res) {
        return 0;
    }

    return getValueRecursive(min, max);
}

/* Before calling this, must ensure that var.expr can be in [min, max] subject to state->constraints
   and m_cons, and [min, max] contains valid value */
uint32_t RestrictedVarEvaluator::getValueRecursive(uint32_t min, uint32_t max) {
    if(min == max) {
        return min;
    }

    uint32_t mid = min+(max-min)/2;

    klee::Solver::Validity lowerContainValidValue = klee::Solver::Unknown;
    klee::Solver::Validity lowerCanBePointed = klee::Solver::Unknown;
    klee::Solver::Validity upperContainValidValue = klee::Solver::Unknown;
    klee::Solver::Validity upperCanBePointed = klee::Solver::Unknown;

    if(m_var.valueSet->isOverlap(min, mid)) {
        lowerContainValidValue = klee::Solver::True;
    }
    else {
        lowerContainValidValue = klee::Solver::False;

        /* We have ensure that [min, max] must contains valid value, since
           it is not in [min, mid], then it must in [mid+1, max] */
        upperContainValidValue = klee::Solver::True;
    }

    if(upperContainValidValue == klee::Solver::Unknown) {
        if(m_var.valueSet->isOverlap(mid+1, max)) {
            upperContainValidValue = klee::Solver::True;
        }
        else {
            upperContainValidValue = klee::Solver::False;
        }
    }

    if(lowerContainValidValue == klee::Solver::True) {
        klee::ref<klee::Expr> rangeBound = getBoundConstraint(m_var.expr, min, mid);
        klee::ref<klee::Expr> totalCons = klee::AndExpr::create(m_cons, rangeBound);

        bool res;
        assert(m_solver->oMayBeTrue(*m_state, totalCons, res));
        if(res) {
            lowerCanBePointed = klee::Solver::True;
        }
        else {
            lowerCanBePointed = klee::Solver::False;
            upperCanBePointed = klee::Solver::True;
        }

        if(lowerCanBePointed == klee::Solver::True) {
            uint32_t value = getValueRecursive(min, mid);
            if(value != 0) {
                return value;
            }
        }
    }

    if(upperContainValidValue == klee::Solver::True) {
        if(upperCanBePointed == klee::Solver::Unknown) {
            klee::ref<klee::Expr> rangeBound = getBoundConstraint(m_var.expr, mid+1, max);
            klee::ref<klee::Expr> totalCons = klee::AndExpr::create(m_cons, rangeBound);

            bool res;
            assert(m_solver->oMayBeTrue(*m_state, totalCons, res));
            if(res) {
                upperCanBePointed = klee::Solver::True;
            }
        }

        if(upperCanBePointed == klee::Solver::True) {
            uint32_t value = getValueRecursive(mid+1, max);
            if(value != 0) {
                return value;
            }
        }
    }

    return 0;
}


bool RestrictedVarEvaluator::imply(
        RestrictedVar precond,
        RestrictedVar postcond) {
    return false;
}

AsgnSpace::AsgnSpace(const AsgnSpace &rhs) {
    copyContent(rhs);
}

AsgnSpace::~AsgnSpace() {
    std::list<AsgnAxis*>::iterator axisIt;
    for(axisIt=axisList.begin(); axisIt!=axisList.end(); axisIt++) {
        AsgnAxis *axis = *axisIt;
        delete axis;
    }

    std::list<AsgnSubspace*>::iterator subspaceIt;
    for(subspaceIt=subspaceStack.begin(); subspaceIt!=subspaceStack.end(); subspaceIt++) {
        AsgnSubspace *subspace = *subspaceIt;
        delete subspace;
    }
}

AsgnSpace& AsgnSpace::operator=(const AsgnSpace &rhs) {
    copyContent(rhs);

    return *this;
}

int AsgnSpace::AsgnAxis::getLevel() {
    return startAddrStack.back().level;
}

void AsgnSpace::AsgnAxis::setLevel(int level) {
    StartAddr &startAddr = startAddrStack.back();

    if(startAddr.level != level) {
        assert(startAddr.level < level);

        startAddrStack.push_back(
                StartAddr(level, startAddr.isSymbolic, startAddr.addr));
    }
}

uint32_t AsgnSpace::AsgnAxis::getCurrAddr() {
    uint32_t addr = startAddrStack.back().addr;
    if(isSearchingSymbolic()) {
        if(addr < deref->validSymbolicAddrSet->front()) {
            addr = deref->validSymbolicAddrSet->front();
        }
    }
    else {
        if(addr < deref->validConcreteAddrSet->front()) {
            addr = deref->validConcreteAddrSet->front();
        }
    }

    return addr;
}

void AsgnSpace::AsgnAxis::setCurrAddr(uint32_t addr) {
    assert(startAddrStack.back().addr <= addr);

    startAddrStack.back().addr = addr;
}

uint32_t AsgnSpace::AsgnAxis::getMaxAddr() {
    if(isSearchingSymbolic()) {
        return deref->validSymbolicAddrSet->back();
    }
    else {
        return deref->validConcreteAddrSet->back();
    }
}

bool AsgnSpace::AsgnAxis::isOverlap(uint32_t min, uint32_t max) {
    if(isSearchingSymbolic()) {
        return deref->validSymbolicAddrSet->isOverlap(min, max);
    }
    else {
        return deref->validConcreteAddrSet->isOverlap(min, max);
    }
}

bool AsgnSpace::AsgnAxis::containValueInAddrRange(uint32_t min, uint32_t max, ValueSet *valueSet) {
    if(isSearchingSymbolic()) {
        return true;
    }
    else {
        return deref->containValueInConcreteBlock(min, max, valueSet);
    }
}

klee::ref<klee::Expr> AsgnSpace::AsgnAxis::getAddrExpr() {
    return deref->addrExpr;
}

klee::ref<klee::Expr> AsgnSpace::AsgnAxis::getValueExpr() {
    return deref->valueExpr;
}

klee::ref<klee::Expr> AsgnSpace::AsgnAxis::readMemory(uint32_t addr) {
    return deref->readMemory(addr);
}

bool AsgnSpace::AsgnAxis::isSearchingSymbolic() {
    return startAddrStack.back().isSymbolic;
}

void AsgnSpace::AsgnAxis::setSearchingSymbolicFinished() {
    StartAddr &startAddr = startAddrStack.back();
    if(startAddr.isSymbolic) {
        startAddr.isSymbolic = false;
        startAddr.addr = deref->validConcreteAddrSet->front();
    }
}

void AsgnSpace::AsgnAxis::popStartAddr(int level) {
    assert(getLevel() == level);
    startAddrStack.pop_back();
}

void AsgnSpace::AsgnAxis::advanceStartAddr(int level) {
    assert(getLevel() == level);

    StartAddr &startAddr = startAddrStack.back();

    /* To avoid overflow. Since 0xffffffff never becomes valid address, this
       should not be a problem */
    assert(startAddr.addr != 0xffffffff);

    /* Add axis constraint to the superSpace, a better way is using iterator of 
       ValidAddrSet */
    startAddr.addr++;

    if(isSearchingSymbolic()) {
        if(startAddr.addr > deref->validSymbolicAddrSet->back()) {
            setSearchingSymbolicFinished();
        }
    }
}

void AsgnSpace::addAxis(SymDeref *deref) {
    AsgnAxis *axis = new AsgnAxis(deref);
    axisList.push_back(axis);

    if(!subspaceStack.empty()) {
        AsgnSubspace *universe = subspaceStack.front();
        universe->updatedAxises.push_back(axis);
    }

    isFinished = false;
}

AsgnSpace::AsgnAxis* AsgnSpace::currentAxis() {
    if(isFinished) {
        return NULL;
    }

    if(subspaceStack.empty()) {
        if(axisList.empty()) {
            return NULL;
        }

        /* Create the first subspace, we must select the target axis for the first
           subspace, this is the place to implement the first selection heuristic 
           in the pseudo code. We just select the first in axisList.*/
        AsgnSubspace *universe = new AsgnSubspace(axisList.begin(),
                klee::ConstantExpr::create(1, klee::Expr::Bool),
                1);
        subspaceStack.push_back(universe);

        /* Add all axises to updatedAxises of the first subspace */
        for(std::list<AsgnAxis*>::iterator it=axisList.begin();
                it!=axisList.end();
                it++) {
            universe->updatedAxises.push_back(*it);
        }
    }

    /* Return the fixed axis of the subspace on top of stack */
    AsgnSubspace *currspace = subspaceStack.back();
    std::list<AsgnAxis*>::iterator it = currspace->axisListIter;
    AsgnAxis *axis = *it;

    /* Before return, must add one "layer" of currspace */
    if(axis->getLevel() != currspace->level) {
        /* The startAddr.first is like a "Modification log", records at which level
           the last modification has been done. */
        axis->setLevel(currspace->level);
        currspace->updatedAxises.push_back(axis);
    }

    return axis;
}

void AsgnSpace::setFeasible() {
    AsgnSubspace *currspace = subspaceStack.back();
    std::list<AsgnAxis*>::iterator it = currspace->axisListIter;
    AsgnAxis *axis = *it;

    it++;
    if(it != axisList.end()) {
        uint32_t addr = axis->getCurrAddr();

        /* Build the constraint for next subspace */
        klee::ref<klee::Expr> memoryContent = axis->readMemory(addr);

        klee::ref<klee::Expr> addrCons = klee::EqExpr::create(
                axis->getAddrExpr(), 
                klee::ConstantExpr::create(addr, klee::Expr::Int32));
        klee::ref<klee::Expr> valueCons = klee::EqExpr::create(axis->getValueExpr(), memoryContent);
        klee::ref<klee::Expr> asgnCons = klee::AndExpr::create(addrCons, valueCons);

        klee::ref<klee::Expr> totalCons = klee::AndExpr::create(asgnCons, currspace->constraint);

        /* Select the target axis for next subspace, this is the place to implement
           the first selection heuristic in the pseudo code. We just select next axis
           in the list, so nothing should be done. */

        /* Push next subspace */
        subspaceStack.push_back(new AsgnSubspace(it, totalCons, currspace->level+1));
    }
    else {
        isFinished = true;
        hasAssignment = true;
    }
}

void AsgnSpace::setInfeasible() {
    AsgnSubspace *currspace = subspaceStack.back();
    subspaceStack.pop_back();

    /* Delete all axis constraints of this subspace */
    for(std::list<AsgnAxis*>::iterator it=currspace->updatedAxises.begin(); 
            it!=currspace->updatedAxises.end(); 
            it++) {
        AsgnAxis *axis = *it;
        axis->popStartAddr(currspace->level);
    }

    /* Delete this subspace */
    delete currspace;

    if(!subspaceStack.empty()) {
        AsgnSubspace *superspace = subspaceStack.back();
        std::list<AsgnAxis*>::iterator it = superspace->axisListIter;
        AsgnAxis *axis = *it;

        axis->advanceStartAddr(superspace->level);
       
        /* Select next axis to evaluate, this is the place to implement the second selection
           heuristic in the pseudo code. Currently, we just select the axis that reported as
           infeasible. This axis will located at the next element in axisList. And it swap with
           current axis */
        std::list<AsgnAxis*>::iterator it2 = it;
        it2++;
        axisList.erase(it);
        superspace->axisListIter = it2;
        it2++;
        axisList.insert(it2, axis);
    }
    else {
        isFinished = true;
        hasAssignment = false;
    }
}

bool AsgnSpace::startFromLastFeasible() {
    if(isFinished == true) {
        if(hasAssignment == true) {
            isFinished = false;
            return true;
        }
        else {
            return false;
        }
    }
    else {
        return true;
    }
}

bool AsgnSpace::finished() {
    return isFinished;
}

klee::ref<klee::Expr> AsgnSpace::currentConstraint() {
    if(isFinished) {
        assert(hasAssignment);

        if(subspaceStack.empty()) {
            return klee::ConstantExpr::create(1, klee::Expr::Bool);
        }
        else {
            AsgnSubspace *lastSubspace = subspaceStack.back();
            AsgnAxis *lastAxis = *(lastSubspace->axisListIter);

            klee::ref<klee::Expr> lastSubspaceCons = lastSubspace->constraint;

            klee::ref<klee::Expr> lastAxisAddrCons = klee::EqExpr::create(
                    lastAxis->getAddrExpr(),
                    klee::ConstantExpr::create(lastAxis->getCurrAddr(), klee::Expr::Int32));
            klee::ref<klee::Expr> lastAxisValueCons = klee::EqExpr::create(
                    lastAxis->getValueExpr(),
                    lastAxis->readMemory(lastAxis->getCurrAddr()));
            klee::ref<klee::Expr> lastAxisCons = klee::AndExpr::create(
                    lastAxisAddrCons, lastAxisValueCons);

            return klee::AndExpr::create(lastSubspaceCons, lastAxisCons);
        }
    }
    else {
        if(subspaceStack.empty()) {
            return klee::ConstantExpr::create(1, klee::Expr::Bool);
        }
        else {
            return subspaceStack.back()->constraint;
        }
    }
}

uint32_t AsgnSpace::numAxises() {
    return axisList.size();
}

void AsgnSpace::dumpAllAxises() {
    std::ofstream fs;
    fs.open("/home/mhhuang/axises");

    std::list<AsgnAxis*>::iterator it;
    for(it=axisList.begin(); it!=axisList.end(); it++) {
        AsgnAxis *axis = *it;
        fs << "Axis L" << std::dec << axis->getLevel() << " " << axis->isSearchingSymbolic() << std::endl;
        fs << std::hex;
        fs << "Address : " << axis->getAddrExpr() << std::endl;
        fs << "Value : " << axis->getValueExpr() << std::endl;
        fs << "Asgn addr : " << axis->getCurrAddr() << std::endl;
        klee::ref<klee::Expr> value = axis->readMemory(axis->getCurrAddr());
        if(!value.isNull()) {
            fs << "Asgn value : " << value << std::endl;
        }
        else {
            fs << "Asgn value : invalid" << std::endl;
        }

        fs << std::endl;
    }

    fs.close();
}

void AsgnSpace::copyContent(const AsgnSpace &rhs) {
    std::list<AsgnAxis*>::iterator naIt;
    for(naIt=axisList.begin(); naIt!=axisList.end(); naIt++) {
        AsgnAxis *axis = *naIt;
        delete axis;
    }
    axisList.clear();

    std::list<AsgnSubspace*>::iterator nsIt;
    for(nsIt=subspaceStack.begin(); nsIt!=subspaceStack.end(); nsIt++) {
        AsgnSubspace *subspace = *nsIt;
        delete subspace;
    }
    subspaceStack.clear();

    /* Copy axisList */
    std::list<AsgnAxis*>::const_iterator oaIt;  // old axis iterator
    for(oaIt=rhs.axisList.begin(); oaIt!=rhs.axisList.end(); oaIt++) {
        AsgnAxis *oldAxis = *oaIt;
        AsgnAxis *newAxis = new AsgnAxis(oldAxis);

        axisList.push_back(newAxis);
    }

    /* Copy subspaceStack */
    std::list<AsgnSubspace*>::const_iterator osIt;
    for(osIt=rhs.subspaceStack.begin(), naIt=axisList.begin();
            osIt!=rhs.subspaceStack.end();
            osIt++, naIt++) {
        AsgnSubspace *oldSpace = *osIt;
        AsgnSubspace *newSpace = new AsgnSubspace(
                naIt, oldSpace->constraint, oldSpace->level);

        subspaceStack.push_back(newSpace);

        /* In current usage of AsgnSpace, the fixed axis (axisListIter) of 
           subspaces must follow the order of axisList, the following code 
           is just for checking this consistency. */
        assert((*(oldSpace->axisListIter))->deref == 
               (*(newSpace->axisListIter))->deref);
    }

    /* Fill updatedAxises of each subspace */
    for(naIt=axisList.begin(); naIt!=axisList.end(); naIt++) {
        AsgnAxis *axis = *naIt;
        std::list<AsgnAxis::StartAddr>::iterator pIt;
        for(pIt=axis->startAddrStack.begin(); pIt!=axis->startAddrStack.end(); pIt++) {
            int level = pIt->level;

            /* There is a special case that subspaceStack is empty, and
               all axises has only one level of startAddrStack */
            if(!subspaceStack.empty()) {
                nsIt = subspaceStack.begin();
                for(int i=1; i<level; i++) {
                    nsIt++;
                    assert(nsIt != subspaceStack.end());
                }
                AsgnSubspace *subspace = *nsIt;

                subspace->updatedAxises.push_back(axis);
            }
            else {
                assert(level == 1);
            }
        }
    }

    isFinished = rhs.isFinished;
    hasAssignment = rhs.hasAssignment;
}

uint32_t AsgnSpaceSearcher::AsgnAxisSearcher::fillAxisAndGetValue(AsgnSpace::AsgnAxis *a, RestrictedVar v, klee::ref<klee::Expr> c) {
    evaluator = RestrictedVarEvaluator(state, solver);
    axis = a;
    var = v;
    if(c.isNull()) {
        cons = klee::ConstantExpr::create(1, klee::Expr::Bool);
    }
    else {
        cons = c;
    }

    uint32_t res;
    if(axis->isSearchingSymbolic()) {
        res = fillAxisAndGetValueAux();
        if(res != 0) {
            return res;
        }

        /* -mhhuang-delete- */
        std::cout << "[FillAxis] " << std::hex << 
            std::setw(0) << std::setfill(' ') << axis->getValueExpr() << 
            " L" << std::dec << axis->getLevel() <<
            " : Symbolic search fail" << std::endl;

        axis->setSearchingSymbolicFinished();
    }

    concreteSearchStartTime = clock();
    res = fillAxisAndGetValueAux();
    return res;
}

#define ADDR_NUM_LIMIT  6
#define VALUE_NUM_LIMIT 6
uint32_t AsgnSpaceSearcher::AsgnAxisSearcher::fillAxisAndGetValueAux() {
    /* Because this function must find the feasible assignment with lowest address in [asgn->addr, 0xffffffff],
       we first restrict the address >= asgn->addr */
    klee::ref<klee::Expr> addrLowerBound = klee::UgeExpr::create(axis->getAddrExpr(), 
            klee::ConstantExpr::create(axis->getCurrAddr(), klee::Expr::Int32));
    klee::ref<klee::Expr> addrUpperBound = klee::UleExpr::create(axis->getAddrExpr(),
            klee::ConstantExpr::create(axis->getMaxAddr(), klee::Expr::Int32));
    klee::ref<klee::Expr> addrRangeBound = klee::AndExpr::create(addrUpperBound, addrLowerBound);

    klee::ref<klee::Expr> totalCons = klee::AndExpr::create(cons, addrRangeBound);

    /* If the restriction can't be satisfied, then no feasible assignment can be found */
    uint32_t res = evaluator.getValue(var, totalCons);
    if(res == 0) {
        return 0;
    }

    ValueSet possibleAddr = evaluator.getValueSet(
            axis->getAddrExpr(), 
            totalCons, 
            var,
            ADDR_NUM_LIMIT);

    /* Because we must find the smallest feasible address, we can use possibleAddr only if
       we know no smaller feasible address exists */
    if(possibleAddr.size() < ADDR_NUM_LIMIT) {
        ValueSet::iterator it;
        for(it=possibleAddr.begin(); it!=possibleAddr.end(); it++) {
            uint32_t addr = *it;
            if(axis->isOverlap(addr, addr)) {
                res = fillAxisAndGetValueRecursive(addr, addr);
                if(res != 0) {
                    return res;
                }
            }
        }

        return 0;
    }

    if(axis->isOverlap(axis->getCurrAddr(), axis->getMaxAddr()) == false) {
        return 0;
    }

    ValueSet possibleValue = evaluator.getValueSet(
            axis->getValueExpr(), 
            totalCons, 
            var, 
            VALUE_NUM_LIMIT);
    /* All possible values are in the set */
    if(possibleValue.size() < VALUE_NUM_LIMIT) {
        possibleValueSet = &possibleValue;
    }
    /* There may be more possible values */
    else {
        possibleValueSet = NULL;
    }

    /* We have checked that var have a valid address subject to cons and addrRangeBound, that
       means addr can fall into [axis->getCurrAddr(), 0xffffffff].
       And we have checked that [axis->getCurrAddr(), 0xffffffff] have valid address. 
       So, the precondition of this call is ensured */
    return fillAxisAndGetValueRecursive(axis->getCurrAddr(), axis->getMaxAddr());
}

#define VALUE_FILTERING_THRESHOLD   1024
/* Before calling this, must ensure axis->deref->addrExpr can falling into [min, max] subject to
   state->constraints, cons, and var can be valid value.
   Also must ensure the range contains at least one valid address */
uint32_t AsgnSpaceSearcher::AsgnAxisSearcher::fillAxisAndGetValueRecursive(uint32_t min, uint32_t max) {
    if(!axis->isSearchingSymbolic()) {
        clock_t passed = clock()-concreteSearchStartTime;
        double seconds = ((double)passed)/CLOCKS_PER_SEC;
        if(seconds > concreteSearchTimeout) {
#if 0
            state->constraints.saveAllConstraints(state->getID());

            g_s2e->getWarningsStream(state) << "Address: " << std::endl <<
                axis->getAddrExpr() << std::endl;

            g_s2e->getWarningsStream(state) << "Value: " << std::endl << 
                axis->getValueExpr() << std::endl;

            g_s2e->getWarningsStream(state) << "Cons: " << std::endl <<
                cons << std::endl;

            g_s2e->getWarningsStream(state) << "Var.expr: " << std::endl <<
                var.expr << std::endl;

            g_s2e->getExecutor()->terminateStateEarly((ExecutionState&)*state, "Terminate due to unsolvability");
#endif

            g_s2e->getWarningsStream(state) << "[FillAxis] " << std::hex << 
                std::setw(0) << std::setfill(' ') << axis->getValueExpr() << 
                " L" << std::dec << axis->getLevel() <<
                " : Timeout" << std::endl;

            return 0;
        }
    }

    if(min == max) {
        uint32_t addr = min;

        klee::ref<klee::Expr> memoryContent = axis->readMemory(addr);

        klee::ref<klee::Expr> addrCons = klee::EqExpr::create(
                axis->getAddrExpr(), 
                klee::ConstantExpr::create(addr, klee::Expr::Int32));
        klee::ref<klee::Expr> valueCons = klee::EqExpr::create(axis->getValueExpr(), memoryContent);
        klee::ref<klee::Expr> asgnCons = klee::AndExpr::create(addrCons, valueCons);

        klee::ref<klee::Expr> totalCons = klee::AndExpr::create(cons, asgnCons);

        uint32_t res = evaluator.getValue(var, totalCons);
        if(res != 0) {
            axis->setCurrAddr(addr);

            return res;
        }

        /* -mhhuang-delete- */
        std::cout << "[FillAxis] " << std::hex << 
            std::setw(0) << std::setfill(' ') << axis->getValueExpr() << 
            " L" << std::dec << axis->getLevel() << std::hex <<
            " : @" << std::setw(8) << std::setfill('0') << addr << " fail" << std::endl;

        return 0;
    }
    else {
        uint32_t mid = min+(max-min)/2;

        klee::Solver::Validity lowerContainValidAddr = klee::Solver::Unknown;
        klee::Solver::Validity lowerCanBePointed = klee::Solver::Unknown;
        klee::Solver::Validity upperContainValidAddr = klee::Solver::Unknown;
        klee::Solver::Validity upperCanBePointed = klee::Solver::Unknown;

        if(axis->isOverlap(min, mid)) {
            lowerContainValidAddr = klee::Solver::True;
        }
        else {
            lowerContainValidAddr = klee::Solver::False;

            /* We have ensure that [min, max] must contains valid address, since
               it is not in [min, mid], then it must in [mid+1, max] */
            upperContainValidAddr = klee::Solver::True;
        }

        if(upperContainValidAddr == klee::Solver::Unknown) {
            if(axis->isOverlap(mid+1, max)) {
                upperContainValidAddr = klee::Solver::True;
            }
            else {
                upperContainValidAddr = klee::Solver::False;
            }
        }

        if(lowerContainValidAddr == klee::Solver::True) {
            /* -mhhuang-delete- */
            clock_t startTime = clock();

            /* If the address range > VALUE_FILTERING_THRESHOLD, always recursive look-in,
               otherwise, check whether the range contains possible value first */
            if(mid-min+1 > VALUE_FILTERING_THRESHOLD ||
                    possibleValueSet == NULL ||
                    axis->containValueInAddrRange(min, mid, possibleValueSet)) {
                klee::ref<klee::Expr> addrInLowerHalf = klee::AndExpr::create(cons, 
                        getBoundConstraint(axis->getAddrExpr(), min, mid));

                uint32_t res = evaluator.getValue(var, addrInLowerHalf);
                if(res != 0) {
                    lowerCanBePointed = klee::Solver::True;
                }
                else {
                    lowerCanBePointed = klee::Solver::False;
                    upperCanBePointed = klee::Solver::True;
                }

                if(lowerCanBePointed == klee::Solver::True) {
                    res = fillAxisAndGetValueRecursive(min, mid);
                    if(res != 0)
                        return res;
                }
            }
            /* -mhhuang-delete- */
            else {
                clock_t passed = clock()-startTime;
                double seconds = ((double)passed)/CLOCKS_PER_SEC;

                std::cout << "[FillAxis] " << 
                    std::setw(6) << std::setfill('0') << std::setprecision(2) << seconds << " " <<
                    std::hex << 
                    std::setw(0) << std::setfill(' ') << axis->getValueExpr() <<
                    " L" << std::dec << axis->getLevel() << std::hex << 
                    " : @0x" << std::setw(8) << std::setfill('0') << min << 
                    " - 0x" << std::setw(8) << std::setfill('0') << mid <<
                    " fail" << std::endl;
            }
        }

        if(upperContainValidAddr == klee::Solver::True) {
            /* -mhhuang-delete- */
            clock_t startTime = clock();

            if(max-mid > VALUE_FILTERING_THRESHOLD ||
                    possibleValueSet == NULL ||
                    axis->containValueInAddrRange(mid+1, max, possibleValueSet)) {
                if(upperCanBePointed == klee::Solver::Unknown) {
                    klee::ref<klee::Expr> addrInUpperHalf = klee::AndExpr::create(cons, 
                            getBoundConstraint(axis->getAddrExpr(), mid+1, max));

                    uint32_t res = evaluator.getValue(var, addrInUpperHalf);
                    if(res != 0) {
                        upperCanBePointed = klee::Solver::True;
                    }
                    else {
                        upperCanBePointed = klee::Solver::False;
                    }
                }

                if(upperCanBePointed == klee::Solver::True) {
                    uint32_t res = fillAxisAndGetValueRecursive(mid+1, max);
                    if(res != 0)
                        return res;;
                }
            }
            /* -mhhuang-delete- */
            else {
                clock_t passed = clock()-startTime;
                double seconds = ((double)passed)/CLOCKS_PER_SEC;

                std::cout << "[FillAxis] " << 
                    std::setw(6) << std::setfill('0') << std::setprecision(2) << seconds << " " <<
                    std::hex << 
                    std::setw(0) << std::setfill(' ') << axis->getValueExpr() <<
                    " L" << std::dec << axis->getLevel() << std::hex <<
                    " : @0x" << std::setw(8) << std::setfill('0') << mid+1 << 
                    " - 0x" << std::setw(8) << std::setfill('0') << max <<
                    " fail" << std::endl;
            }
        }

        return 0; 
    }
}

uint32_t AsgnSpaceSearcher::fillSpaceAndGetValue(AsgnSpace *space, RestrictedVar var) {
    if(!space->startFromLastFeasible()) {
        return 0;
    }

    RestrictedVarEvaluator evaluator(state, solver);
    uint32_t res = evaluator.getValue(var);
    if(res == 0) {
        return 0;
    }

    AsgnAxisSearcher axisSearcher(state, solver);
    axisSearcher.setConcreteSearchTimeout(concreteSearchTimeout);

    while(1) {
        AsgnSpace::AsgnAxis *axis = space->currentAxis();
        if(axis == NULL) {
            break;
        }

        /* -mhhuang-delete- */
        clock_t start = clock();

        res = axisSearcher.fillAxisAndGetValue(axis, var, space->currentConstraint());

        /* -mhhuang-delete- */
        clock_t passed = clock()-start;
        double seconds = ((double)passed)/CLOCKS_PER_SEC;

        if(res != 0) {
            /* -mhhuang-delete- */
            std::cout << "[Axis] " << std::fixed <<
                std::setw(6) << std::setfill('0') << std::setprecision(2) << seconds << " " <<
                std::hex << 
                std::setw(0) << std::setfill(' ') << axis->getValueExpr() << 
                " L" << std::dec << axis->getLevel() << std::hex <<
                " : @" << std::setw(8) << std::setfill('0') << axis->getCurrAddr() << " " <<  
                std::setw(0) << std::setfill(' ') << axis->readMemory(axis->getCurrAddr()) << 
                std::endl;

            space->setFeasible();
        }
        else {
            /* -mhhuang-delete- */
            std::cout << "[Axis] " << std::fixed <<
                std::setw(6) << std::setfill('0') << std::setprecision(2) << seconds << " " <<
                std::hex << 
                std::setw(0) << std::setfill(' ') << axis->getValueExpr() << 
                " L" << std::dec << axis->getLevel() << std::hex << 
                " : No feasible asgn, backtrack ..." << 
                std::endl;

            space->setInfeasible();
        }
    }

    return res;
}
#endif  // __KS_MHHUANG_SYM_READ__

S2EExecutionState::S2EExecutionState(klee::KFunction *kf) :
        klee::ExecutionState(kf),
#ifdef __KS_MHHUANG_STATE_FORK__
        m_parentState(NULL), m_childState(NULL), 
        m_waitReturnValue(-1),
#endif
        m_stateID(s_lastStateID++),
        m_symbexEnabled(true), m_startSymbexAtPC((uint64_t) -1),
        m_active(true), m_runningConcrete(true),
        m_cpuRegistersState(NULL), m_cpuSystemState(NULL),
        m_cpuRegistersObject(NULL), m_cpuSystemObject(NULL),
        m_dirtyMask(NULL), m_qemuIcount(0), m_lastS2ETb(NULL),
        m_lastMergeICount((uint64_t)-1),
        m_needFinalizeTBExec(false)
#ifdef __KS_MHHUANG_SYM_READ__
        , m_needUpdateAsgnSpace(false)
#endif
{
    m_deviceState = new S2EDeviceState();
    m_timersState = new TimersState;
    m_isHack = false;
}

S2EExecutionState::~S2EExecutionState()
{
    if(m_isHack)
        return;

    if(m_lastS2ETb != NULL) {
        assert(false);
    }

    PluginStateMap::iterator it;
    g_s2e->getDebugStream() << "Deleting state " << std::dec <<
            m_stateID << " 0x" << std::hex << this << std::endl;

    //print_stacktrace();

    for(it = m_PluginState.begin(); it != m_PluginState.end(); ++it) {
        g_s2e->getDebugStream() << "Deleting state info 0x" << std::hex << it->second << std::endl;
        delete it->second;
    }

    g_s2e->refreshPlugins();

    //XXX: This cannot be done, as device states may refer to each other
    //delete m_deviceState;

    delete m_timersState;
}

#ifdef __KS_MHHUANG_SYM_READ__
void S2EExecutionState::addSymDeref(SymDeref *deref) {
    m_asgnSpace.addAxis(deref);
    m_needUpdateAsgnSpace = true;
}

uint32_t S2EExecutionState::getValue(
        klee::TimingSolver &solver, 
        RestrictedVar var) {
    /* This functionality for concolic mode is not implemented yet */
    assert(!isConcolicMode);

    constraints.startSymbolicEvaluate();

    AsgnSpaceSearcher asgnSpaceSearcher(this, &solver);
    asgnSpaceSearcher.setConcreteSearchTimeout(60);

    AsgnSpace asgnSpace = m_asgnSpace;

    uint32_t value = asgnSpaceSearcher.fillSpaceAndGetValue(
            &asgnSpace, var);

    constraints.endSymbolicEvaluate();

    return value;
}

void S2EExecutionState::updateAsgnSpace(klee::TimingSolver &solver) const {
    if(m_needUpdateAsgnSpace) {
        std::cout << "[Update Asgn space] Current " << std::dec <<
            m_asgnSpace.numAxises() << " axises" << std::endl;

        constraints.startPermanentEvaluate();

        AsgnSpaceSearcher asgnSpaceSearcher(this, &solver);

        uint32_t res = asgnSpaceSearcher.fillSpaceAndGetValue(&m_asgnSpace, 
                RestrictedVar(klee::ConstantExpr::create(1, klee::Expr::Bool)));
        assert(res != 0);
        m_needUpdateAsgnSpace = false;

        constraints.endPermanentEvaluate();
    }
}
#endif

bool S2EExecutionState::evaluate(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, 
        klee::Solver::Validity &result) const {
    /* -mhhuang-delete- */
    if(!isa<klee::ConstantExpr>(expr)) {
        int aa = 33;
        int bb = aa;
    }

    bool res, success;

    success = mayBeTrue(solver, expr, res);
    if(!success) {
        return false;
    }
    if(!res) {
        /* No assignment satisfies expr, then expr must be false
           This is based on that there must have an assignment that satisfies current path constraint */
        result = Solver::False;
        return true;
    }

    success = mayBeFalse(solver, expr, res);
    if(!success) {
        return false;
    }
    if(!res) {
        result = Solver::True;
        return true;
    }

    /* In concolic mode, it's impossible to return Solver::Unknown */
    if(isConcolicMode)
        assert(false);

    result = Solver::Unknown;
    return true;
}

bool S2EExecutionState::mustBeTrue(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, 
        bool &result) const {
    /* If no assignment can satisfy (not expr) then expr must be true.
       This is based on that there must have an assignment that satisfies current path constraint.
       No assignment satisfy (not expr) && exist assignment satisfy path constraint =>
         all possible assignments satisfy expr 
       So we must ensure every dereference and every forked state are feasible! */
    bool success = mayBeFalse(solver, expr, result);
    result = !result;
    return success;
}

bool S2EExecutionState::mustBeFalse(klee::TimingSolver &solver, 
        klee::ref<klee::Expr> expr, 
        bool &result) const {
    bool success = mayBeTrue(solver, expr, result);
    result = !result;
    return success;
}

bool S2EExecutionState::mayBeTrue(klee::TimingSolver &solver, 
        klee::ref<klee::Expr> expr, 
        bool &result) const {
    if(isConcolicMode || isa<klee::ConstantExpr>(expr)) {
        constraints.startConcolicEvaluate();
        bool success = solver.oMayBeTrue(*this, expr, result);
        constraints.endConcolicEvaluate();

        return success;
    }
    else {
#ifdef __KS_MHHUANG_SYM_READ__
        updateAsgnSpace(solver);
#endif
        bool success = false;
        constraints.startSymbolicEvaluate();
#ifdef __KS_MHHUANG_SYM_READ__
        /* -mhhuang-delete- */
        std::cout << "[MayBeTrue] " << std::setfill(' ') << expr << std::endl;

        AsgnSpaceSearcher asgnSpaceSearcher(this, &solver);
        asgnSpaceSearcher.setConcreteSearchTimeout(60);

        /* Must implement the assignment operator */
        AsgnSpace asgnSpace = m_asgnSpace;

        uint32_t res = asgnSpaceSearcher.fillSpaceAndGetValue(&asgnSpace, RestrictedVar(expr));
        if(res != 0) {
            result = true;

            /* -mhhuang-delete- */
            std::cout << "[MayBeTrue] Result is true" << std::endl;
        }
        else {
            result = false;

             /* -mhhuang-delete- */
            std::cout << "[MayBeTrue] Result is false" << std::endl;
        }

        success = true;
#else
        success = solver.oMayBeTrue(*this, expr, result);
#endif
        constraints.endSymbolicEvaluate();

        return success;
    }
}

bool S2EExecutionState::mayBeFalse(klee::TimingSolver &solver, klee::ref<klee::Expr> expr, 
        bool &result) const {
    return mayBeTrue(solver, klee::Expr::createIsZero(expr), result);
}

bool S2EExecutionState::getValue(klee::TimingSolver &solver, klee::ref<klee::Expr> expr,
        klee::ref<klee::ConstantExpr> &result) const {
    if(isConcolicMode || isa<klee::ConstantExpr>(expr)) {
        constraints.startConcolicEvaluate();
        bool success = solver.oGetValue(*this, expr, result);
        constraints.endConcolicEvaluate();

        return success;
    }
    else {
#ifdef __KS_MHHUANG_SYM_READ__
        updateAsgnSpace(solver);
#endif
        bool success = false;
        constraints.startSymbolicEvaluate();
#ifdef __KS_MHHUANG_SYM_READ__
        /* -mhhuang-delete- */
        std::cout << "[GetValue] " << std::setfill(' ') << expr << std::endl;

        AsgnSpaceSearcher asgnSpaceSearcher(this, &solver);

        /* Must implement the assignment operator 
           Can not just use m_asgnSpace because there may be temp constraints */
        AsgnSpace asgnSpace = m_asgnSpace;

        uint32_t res = asgnSpaceSearcher.fillSpaceAndGetValue(&asgnSpace, 
                RestrictedVar(klee::ConstantExpr::create(1, klee::Expr::Bool)));
        assert(res != 0);

        std::vector<klee::ref<klee::Expr> > tempConstraints = getTempConstraints();
        addTempConstraint(asgnSpace.currentConstraint());
        success = solver.oGetValue(*this, expr, result);
        setTempConstraints(tempConstraints);
#else
        success = solver.oGetValue(*this, expr, result);
#endif
        constraints.endSymbolicEvaluate();

        return success;
    }
}

bool S2EExecutionState::getInitialValues(TimingSolver &solver, 
        const std::vector<const Array*> &objects, 
        std::vector< std::vector<unsigned char> > &result) const {
    if(isConcolicMode) {
        constraints.startConcolicEvaluate();
        bool success = solver.oGetInitialValues(*this, objects, result);
        constraints.endConcolicEvaluate();

        return success;
    }
    else {
#ifdef __KS_MHHUANG_SYM_READ__
        updateAsgnSpace(solver);
#endif
        bool success = false;
        constraints.startSymbolicEvaluate();
#ifdef __KS_MHHUANG_SYM_READ__
        std::cout << "[GetInitValue]" << std::endl;

        AsgnSpaceSearcher asgnSpaceSearcher(this, &solver);

        /* Must implement the assignment operator */
        AsgnSpace asgnSpace = m_asgnSpace;

        uint32_t res = asgnSpaceSearcher.fillSpaceAndGetValue(&asgnSpace, 
                RestrictedVar(klee::ConstantExpr::create(1, klee::Expr::Bool)));
        assert(res != 0);

        std::vector<klee::ref<klee::Expr> > tempConstraints = getTempConstraints();
        addTempConstraint(asgnSpace.currentConstraint());
        success = solver.oGetInitialValues(*this, objects, result);
        setTempConstraints(tempConstraints);
#else
        success = solver.oGetInitialValues(*this, objects, result);
#endif
        constraints.endSymbolicEvaluate();

        return success;
    }
}

/* An ugly hack to let Executor::getSymbolicSolution works */
ExecutionState* S2EExecutionState::getClone() const { 
    S2EExecutionState *s = new S2EExecutionState(*this); 
    s->m_isHack = true;
    return s;
}

void S2EExecutionState::addConstraint(klee::ref<klee::Expr> e) const {
#ifdef __MHHUANG_DISCARD_KERNEL__
    if(getPc() >= KERNEL_SPACE) {
        return;
    }
#endif

    if(!isa<klee::ConstantExpr>(e)) {
        addPermanentConstraintAndClearTempConstraints(e);
    }
}

void S2EExecutionState::addTempConstraint(klee::ref<klee::Expr> e) const {
    constraints.addTempConstraint(e);
}

void S2EExecutionState::clearTempConstraints() const {
    constraints.clearTempConstraints();
}

std::vector<klee::ref<klee::Expr> > S2EExecutionState::getTempConstraints() const {
    return constraints.getTempConstraints();
}

void S2EExecutionState::setTempConstraints(std::vector<klee::ref<klee::Expr> > tempCons) const {
    constraints.setTempConstraints(tempCons);
}

void S2EExecutionState::addPermanentConstraintAndClearTempConstraints(klee::ref<klee::Expr> e) const {
#ifdef __KS_MHHUANG_SYM_READ__
    /* We only step fowrard our starting point when the constraint is permanent, because
       the step can not be inverted, can not apply to temp constraint which may be removed 
       later */
    m_needUpdateAsgnSpace = true;
#endif
    constraints.addPermanentConstraintAndClearTempConstraints(e);
}

void S2EExecutionState::enableSymbolicExecution()
{
    if (m_symbexEnabled) {
        return;
    }

    for(std::vector<uint64_t>::iterator it = concrete_byte.begin() ; it != concrete_byte.end() ; it++)
    {
      ObjectPair op = addressSpace.findObject(*it & S2E_RAM_OBJECT_MASK);
      unsigned int offset = (*it & ~S2E_RAM_OBJECT_MASK);                       
      klee::ObjectState *wos = addressSpace.getWriteable(op.first, op.second);   
      wos->markByteSymbolic(offset);                                                    
      wos->markByteUnflushed(offset);                                                   
    }
    concrete_byte.clear();

    m_symbexEnabled = true;

    g_s2e->getMessagesStream(this) << "Enabled symbex"
            << " at pc = " << (void*) getPc() << std::endl;

}

void S2EExecutionState::disableSymbolicExecution()
{
    if (!m_symbexEnabled) {
        return;
    }

    m_symbexEnabled = false;

    g_s2e->getMessagesStream(this) << "Disabled symbex"
            << " at pc = " << (void*) getPc() << std::endl;

}

void S2EExecutionState::enableForking()
{
    if (!forkDisabled) {
        return;
    }

    forkDisabled = false;

    //g_s2e->getMessagesStream(this) << "Enabled forking"
    //        << " at pc = " << (void*) getPc() << std::endl;
}

void S2EExecutionState::disableForking()
{
    if (forkDisabled) {
        return;
    }

    forkDisabled = true;

    //g_s2e->getMessagesStream(this) << "Disabled forking"
    //        << " at pc = " << (void*) getPc() << std::endl;
}


void S2EExecutionState::addressSpaceChange(const klee::MemoryObject *mo,
                        const klee::ObjectState *oldState,
                        klee::ObjectState *newState)
{
#ifdef S2E_ENABLE_S2E_TLB
    if(mo->size == S2E_RAM_OBJECT_SIZE && oldState) {
        assert(m_cpuSystemState && m_cpuSystemObject);

        CPUX86State* cpu = m_active ?
                (CPUX86State*)(m_cpuSystemState->address
                              - offsetof(CPUX86State, eip)) :
                (CPUX86State*)(m_cpuSystemObject->getConcreteStore(true)
                              - offsetof(CPUX86State, eip));

        for(unsigned i=0; i<NB_MMU_MODES; ++i) {
            for(unsigned j=0; j<CPU_S2E_TLB_SIZE; ++j) {
                if(cpu->s2e_tlb_table[i][j].objectState == (void*) oldState) {
                    assert(newState); // we never delete memory pages
                    cpu->s2e_tlb_table[i][j].objectState = newState;
                    if(!mo->isSharedConcrete) {
                        cpu->s2e_tlb_table[i][j].addend =
                                (cpu->s2e_tlb_table[i][j].addend & ~1)
                                - (uintptr_t) oldState->getConcreteStore(true)
                                + (uintptr_t) newState->getConcreteStore(true);
                        if(addressSpace.isOwnedByUs(newState))
                            cpu->s2e_tlb_table[i][j].addend |= 1;
                    }
                }
            }
        }
    }
#endif
}

ExecutionState* S2EExecutionState::clone()
{
    // When cloning, all ObjectState becomes not owned by neither of states
    // This means that we must clean owned-by-us flag in S2E TLB
    assert(m_active && m_cpuSystemState);
#ifdef S2E_ENABLE_S2E_TLB
    CPUX86State* cpu = (CPUX86State*)(m_cpuSystemState->address
                          - offsetof(CPUX86State, eip));

    for(unsigned i=0; i<NB_MMU_MODES; ++i) {
        for(unsigned j=0; j<CPU_S2E_TLB_SIZE; ++j) {
            ObjectState* os = static_cast<ObjectState*>(
                    cpu->s2e_tlb_table[i][j].objectState);
            if(os && !os->getObject()->isSharedConcrete) {
                cpu->s2e_tlb_table[i][j].addend &= ~1;
            }
        }
    }
#endif

    S2EExecutionState *ret = new S2EExecutionState(*this);
    ret->addressSpace.state = ret;

    S2EDeviceState *dev1, *dev2;
    m_deviceState->clone(&dev1, &dev2);
    m_deviceState = dev1;
    ret->m_deviceState = dev2;

    if(m_lastS2ETb)
        m_lastS2ETb->refCount += 1;

    ret->m_stateID = s_lastStateID++;

    ret->m_timersState = new TimersState;
    *ret->m_timersState = *m_timersState;

    // Clone the plugins
    PluginStateMap::iterator it;
    ret->m_PluginState.clear();
    for(it = m_PluginState.begin(); it != m_PluginState.end(); ++it) {
        ret->m_PluginState.insert(std::make_pair((*it).first, (*it).second->clone()));
    }

    // This objects are not in TLB and won't cause any changes to it
    ret->m_cpuRegistersObject = ret->addressSpace.getWriteable(
                            m_cpuRegistersState, m_cpuRegistersObject);
    ret->m_cpuSystemObject = ret->addressSpace.getWriteable(
                            m_cpuSystemState, m_cpuSystemObject);

    m_cpuRegistersObject = addressSpace.getWriteable(
                            m_cpuRegistersState, m_cpuRegistersObject);
    m_cpuSystemObject = addressSpace.getWriteable(
                            m_cpuSystemState, m_cpuSystemObject);

    return ret;
}

ref<Expr> S2EExecutionState::getEax()
{
  return readCpuRegister(offsetof(CPUState, regs[R_EAX]), klee::Expr::Int32);
}

ref<Expr> S2EExecutionState::readCpuRegister(unsigned offset,
                                             Expr::Width width) const
{
    assert((width == 1 || (width&7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));

    if(!m_runningConcrete || !m_cpuRegistersObject->isConcrete(offset, width)) {
        return m_cpuRegistersObject->read(offset, width);
    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        uint64_t ret = 0;
        memcpy((void*) &ret, (void*) (m_cpuRegistersState->address + offset),
                       Expr::getMinBytesForWidth(width));
        return ConstantExpr::create(ret, width);
    }
}

void S2EExecutionState::writeCpuRegister(unsigned offset,
                                         klee::ref<klee::Expr> value)
{
    unsigned width = value->getWidth();
    assert((width == 1 || (width&7) == 0) && width <= 64);
    assert(offset + Expr::getMinBytesForWidth(width) <= CPU_OFFSET(eip));

    if(!m_runningConcrete || !m_cpuRegistersObject->isConcrete(offset, width)) {
        m_cpuRegistersObject->write(offset, value);

    } else {
        /* XXX: should we check getSymbolicRegisterMask ? */
        assert(isa<ConstantExpr>(value) &&
               "Can not write symbolic values to registers while executing"
               " in concrete mode. TODO: fix it by longjmping to main loop");
        ConstantExpr* ce = cast<ConstantExpr>(value);
        uint64_t v = ce->getZExtValue(64);
        memcpy((void*) (m_cpuRegistersState->address + offset), (void*) &v,
                    Expr::getMinBytesForWidth(ce->getWidth()));
    }
}

bool S2EExecutionState::readCpuRegisterConcrete(unsigned offset,
                                                void* buf, unsigned size)
{
    assert(size <= 8);
    ref<Expr> expr = readCpuRegister(offset, size*8);
    if(!isa<ConstantExpr>(expr))
        return false;
    uint64_t value = cast<ConstantExpr>(expr)->getZExtValue();
    memcpy(buf, &value, size);
    return true;
}

void S2EExecutionState::writeCpuRegisterConcrete(unsigned offset,
                                                 const void* buf, unsigned size)
{
    uint64_t value = 0;
    memcpy(&value, buf, size);
    writeCpuRegister(offset, ConstantExpr::create(value, size*8));
}

uint64_t S2EExecutionState::readCpuState(unsigned offset,
                                         unsigned width) const
{
    assert((width == 1 || (width&7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUX86State, eip));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUX86State));

    const uint8_t* address;
    if(m_active) {
        address = (uint8_t*) m_cpuSystemState->address - CPU_OFFSET(eip);
    } else {
        address = m_cpuSystemObject->getConcreteStore(); assert(address);
        address -= CPU_OFFSET(eip);
    }

    uint64_t ret = 0;
    memcpy((void*) &ret, address + offset, Expr::getMinBytesForWidth(width));

    if(width == 1)
        ret &= 1;

    return ret;
}

void S2EExecutionState::writeCpuState(unsigned offset, uint64_t value,
                                      unsigned width)
{
    assert((width == 1 || (width&7) == 0) && width <= 64);
    assert(offset >= offsetof(CPUX86State, eip));
    assert(offset + Expr::getMinBytesForWidth(width) <= sizeof(CPUX86State));

    uint8_t* address;
    if(m_active) {
        address = (uint8_t*) m_cpuSystemState->address - CPU_OFFSET(eip);
    } else {
        address = m_cpuSystemObject->getConcreteStore(); assert(address);
        address -= CPU_OFFSET(eip);
    }

    if(width == 1)
        value &= 1;
    memcpy(address + offset, (void*) &value, Expr::getMinBytesForWidth(width));
}

//Get the program counter in the current state.
//Allows plugins to retrieve it in a hardware-independent manner.
uint64_t S2EExecutionState::getPc() const
{
    return readCpuState(CPU_OFFSET(eip), 8*sizeof(target_ulong));
}

void S2EExecutionState::setPc(uint64_t pc)
{
    writeCpuState(CPU_OFFSET(eip), pc, sizeof(target_ulong)*8);
}

void S2EExecutionState::setSp(uint64_t sp)
{
    writeCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]), &sp, sizeof(target_ulong));
}

uint64_t S2EExecutionState::getSp() const
{
    ref<Expr> e = readCpuRegister(CPU_OFFSET(regs[R_ESP]),
                                  8*sizeof(target_ulong));
    return cast<ConstantExpr>(e)->getZExtValue(64);
}

uint64_t S2EExecutionState::getBp() const
{
    ref<Expr> e = readCpuRegister(CPU_OFFSET(regs[R_EBP]),
                                  8*sizeof(target_ulong));
    return cast<ConstantExpr>(e)->getZExtValue(64);
}

uint64_t S2EExecutionState::getAx() const
{
    ref<Expr> e = readCpuRegister(CPU_OFFSET(regs[R_EAX]),
                                  8*sizeof(target_ulong));
    return cast<ConstantExpr>(e)->getZExtValue(64);
}
//This function must be called just after the machine call instruction
//was executed.
//XXX: assumes x86 architecture.
bool S2EExecutionState::bypassFunction(unsigned paramCount)
{
    uint64_t retAddr;
    if (!getReturnAddress(&retAddr)) {
        return false;
    }

    uint32_t newSp = getSp() + (paramCount+1)*sizeof(uint32_t);

    setSp(newSp);
    setPc(retAddr);
    return true;
}

//May be called right after the machine call instruction
//XXX: assumes x86 architecture
bool S2EExecutionState::getReturnAddress(uint64_t *retAddr)
{
    *retAddr = 0;
    if (!readMemoryConcrete(getSp(), retAddr, sizeof(uint32_t))) {
        g_s2e->getDebugStream() << "Could not get the return address " << std::endl;
        return false;
    }
    return true;
}

void S2EExecutionState::dumpStack(unsigned count)
{
    dumpStack(getSp());
}

void S2EExecutionState::dumpStack(unsigned count, uint64_t sp)
{
    std::ostream &os = g_s2e->getDebugStream();

    os << "Dumping stack @0x" << std::hex << sp << std::endl;

    for (unsigned i=0; i<count; ++i) {
        klee::ref<klee::Expr> val = readMemory(sp + i * sizeof(uint32_t), klee::Expr::Int32);
        klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(val);
        if (ce) {
            os << std::hex << "0x" << sp + i * sizeof(uint32_t) << " 0x" << std::setw(sizeof(uint32_t)*2) << std::setfill('0') << val;
            os << std::setfill(' ');
        }else {
            os << std::hex << "0x" << sp + i * sizeof(uint32_t) << val;
        }
        os << std::endl;
    }
}


uint64_t S2EExecutionState::getTotalInstructionCount()
{
    if (!m_cpuSystemState) {
        return 0;
    }
    return readCpuState(CPU_OFFSET(s2e_icount), 8*sizeof(uint64_t));
}


TranslationBlock *S2EExecutionState::getTb() const
{
    return (TranslationBlock*)
            readCpuState(CPU_OFFSET(s2e_current_tb), 8*sizeof(void*));
}

uint64_t S2EExecutionState::getPid() const
{
    return readCpuState(offsetof(CPUX86State, cr[3]), 8*sizeof(target_ulong));
}

uint64_t S2EExecutionState::getSymbolicRegistersMask() const
{
    const ObjectState* os = m_cpuRegistersObject;
    if(os->isAllConcrete())
        return 0;

    uint64_t mask = 0;
    /* XXX: x86-specific */
    for(int i = 0; i < 8; ++i) { /* regs */
        if(!os->isConcrete(i*4, 4*8))
            mask |= (1 << (i+5));
    }
    if(!os->isConcrete( 8*4, 4*8)) // cc_op
        mask |= (1 << 1);
    if(!os->isConcrete( 9*4, 4*8)) // cc_src
        mask |= (1 << 2);
    if(!os->isConcrete(10*4, 4*8)) // cc_dst
        mask |= (1 << 3);
    if(!os->isConcrete(11*4, 4*8)) // cc_tmp
        mask |= (1 << 4);
    return mask;
}

/* XXX: this function belongs to S2EExecutor */
bool S2EExecutionState::readMemoryConcrete(uint64_t address, void *buf,
                                   uint64_t size, AddressType addressType)
{
    uint8_t *d = (uint8_t*)buf;
    while (size>0) {
        ref<Expr> v = readMemory(address, Expr::Int8, addressType);
        if (v.isNull() || !isa<ConstantExpr>(v)) {
            return false;
        }
        *d = (uint8_t)cast<ConstantExpr>(v)->getZExtValue(8);
        size--;
        d++;
        address++;
    }
    return true;
}

bool S2EExecutionState::writeMemoryConcrete(uint64_t address, void *buf,
                                   uint64_t size, AddressType addressType)
{
    uint8_t *d = (uint8_t*)buf;
    while (size>0) {
        klee::ref<klee::ConstantExpr> val = klee::ConstantExpr::create(*d, klee::Expr::Int8);
        bool b = writeMemory(address, val,  addressType);
        if (!b) {
            return false;
        }
        size--;
        d++;
        address++;
    }
    return true;
}

uint64_t S2EExecutionState::getPhysicalAddress(uint64_t virtualAddress) const
{
    assert(m_active && "Can not use getPhysicalAddress when the state"
                       " is not active (TODO: fix it)");
    target_phys_addr_t physicalAddress =
        cpu_get_phys_page_debug(env, virtualAddress & TARGET_PAGE_MASK);
    if(physicalAddress == (target_phys_addr_t) -1)
        return (uint64_t) -1;

    return physicalAddress | (virtualAddress & ~TARGET_PAGE_MASK);
}

uint64_t S2EExecutionState::getHostAddress(uint64_t address,
                                           AddressType addressType) const
{
    if(addressType != HostAddress) {
        uint64_t hostAddress = address & TARGET_PAGE_MASK;
        if(addressType == VirtualAddress) {
            hostAddress = getPhysicalAddress(hostAddress);
            if(hostAddress == (uint64_t) -1)
                return (uint64_t) -1;
        }

        /* We can not use qemu_get_ram_ptr directly. Mapping of IO memory
           can be modified after memory registration and qemu_get_ram_ptr will
           return incorrect values in such cases */
        hostAddress = (uint64_t) qemu_get_phys_ram_ptr(hostAddress);
        if(!hostAddress)
            return (uint64_t) -1;

        return hostAddress | (address & ~TARGET_PAGE_MASK);

    } else {
        return address;
    }
}

bool S2EExecutionState::readString(uint64_t address, std::string &s, unsigned maxLen)
{
    s = "";
    do {
        uint8_t c;
        SREADR(this, address, c);

        if (c) {
            s = s + (char)c;
        }else {
            return true;
        }
        address++;
        maxLen--;
    }while(maxLen>=0);
    return true;
}

bool S2EExecutionState::readUnicodeString(uint64_t address, std::string &s, unsigned maxLen)
{
    s = "";
    do {
        uint16_t c;
        SREADR(this, address, c);

        if (c) {
            s = s + (char)c;
        }else {
            return true;
        }

        address+=2;
        maxLen--;
    }while(maxLen>=0);
    return true;
}

ref<Expr> S2EExecutionState::readMemory(uint64_t address,
                            Expr::Width width, AddressType addressType) const
{
    assert(width == 1 || (width & 7) == 0);
    uint64_t size = width / 8;

    uint64_t pageOffset = address & ~S2E_RAM_OBJECT_MASK;
    if(pageOffset + size <= S2E_RAM_OBJECT_SIZE) {
        /* Fast path: read belongs to one MemoryObject */
        uint64_t hostAddress = getHostAddress(address, addressType);
        if(hostAddress == (uint64_t) -1)
            return ref<Expr>(0);

        ObjectPair op = addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);

        assert(op.first && op.first->isUserSpecified
               && op.first->size == S2E_RAM_OBJECT_SIZE);

        return op.second->read(pageOffset, width);
    } else {
        /* Access spawns multiple MemoryObject's (TODO: could optimize it) */
        ref<Expr> res(0);
        for(unsigned i = 0; i != size; ++i) {
            unsigned idx = klee::Context::get().isLittleEndian() ?
                           i : (size - i - 1);
            ref<Expr> byte = readMemory8(address + idx, addressType);
            if(byte.isNull()) return ref<Expr>(0);
            res = idx ? ConcatExpr::create(byte, res) : byte;
        }
        return res;
    }
}

ref<Expr> S2EExecutionState::readMemory8(uint64_t address,
                                         AddressType addressType) const
{
    uint64_t hostAddress = getHostAddress(address, addressType);
    if(hostAddress == (uint64_t) -1)
        return ref<Expr>(0);

    ObjectPair op = addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);

    assert(op.first && op.first->isUserSpecified
           && op.first->size == S2E_RAM_OBJECT_SIZE);

    return op.second->read8(hostAddress & ~S2E_RAM_OBJECT_MASK);
}

bool S2EExecutionState::writeMemory(uint64_t address,
                                    ref<Expr> value,
                                    AddressType addressType)
{
    Expr::Width width = value->getWidth();
    assert(width == 1 || (width & 7) == 0);
    ConstantExpr *constantExpr = dyn_cast<ConstantExpr>(value);
    if(constantExpr && width <= 64) {
        // Concrete write of supported width
        uint64_t val = constantExpr->getZExtValue();
        switch (width) {
            case Expr::Bool:
            case Expr::Int8:  return writeMemory8 (address, val, addressType);
            case Expr::Int16: return writeMemory16(address, val, addressType);
            case Expr::Int32: return writeMemory32(address, val, addressType);
            case Expr::Int64: return writeMemory64(address, val, addressType);
            default: assert(0);
        }
        return false;

    } else if(width == Expr::Bool) {
        // Boolean write is a special case
        return writeMemory8(address, ZExtExpr::create(value, Expr::Int8),
                            addressType);

    } else if((address & ~S2E_RAM_OBJECT_MASK) + (width / 8) <= S2E_RAM_OBJECT_SIZE) {
        // All bytes belong to a single MemoryObject

        uint64_t hostAddress = getHostAddress(address, addressType);
        if(hostAddress == (uint64_t) -1)
            return false;

        ObjectPair op = addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);

        assert(op.first && op.first->isUserSpecified
               && op.first->size == S2E_RAM_OBJECT_SIZE);

        ObjectState *wos = addressSpace.getWriteable(op.first, op.second);
        wos->write(hostAddress & ~S2E_RAM_OBJECT_MASK, value);
    } else {
        // Slowest case (TODO: could optimize it)
        unsigned numBytes = width / 8;
        for(unsigned i = 0; i != numBytes; ++i) {
            unsigned idx = Context::get().isLittleEndian() ?
                           i : (numBytes - i - 1);
            if(!writeMemory8(address + idx,
                    ExtractExpr::create(value, 8*i, Expr::Int8), addressType)) {
                return false;
            }
        }
    }
    return true;
}

bool S2EExecutionState::writeMemory8(uint64_t address,
                                     ref<Expr> value, AddressType addressType)
{
    assert(value->getWidth() == 8);

    uint64_t hostAddress = getHostAddress(address, addressType);
    if(hostAddress == (uint64_t) -1)
        return false;
  //  g_s2e->getMessagesStream(this) << "address " << address << "host " << hostAddress <<std::endl;
    ObjectPair op = addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);

    assert(op.first && op.first->isUserSpecified
           && op.first->size == S2E_RAM_OBJECT_SIZE);

    ObjectState *wos = addressSpace.getWriteable(op.first, op.second);
    wos->write(hostAddress & ~S2E_RAM_OBJECT_MASK, value);
     //g_s2e->getMessagesStream(this) << op.second->isByteKnownSymbolic(hostAddress & ~S2E_RAM_OBJECT_MASK) << std::endl;
    return true;
}

bool S2EExecutionState::writeMemory(uint64_t address,
                    uint8_t* buf, Expr::Width width, AddressType addressType)
{
    assert((width & 7) == 0);
    uint64_t size = width / 8;

    uint64_t pageOffset = address & ~S2E_RAM_OBJECT_MASK;
    if(pageOffset + size <= S2E_RAM_OBJECT_SIZE) {
        /* Fast path: write belongs to one MemoryObject */

        uint64_t hostAddress = getHostAddress(address, addressType);
        if(hostAddress == (uint64_t) -1)
            return false;

        ObjectPair op = addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);

        assert(op.first && op.first->isUserSpecified
               && op.first->size == S2E_RAM_OBJECT_SIZE);

        ObjectState *wos = addressSpace.getWriteable(op.first, op.second);
        for(uint64_t i = 0; i < width / 8; ++i)
            wos->write8(pageOffset + i, buf[i]);

    } else {
        /* Access spawns multiple MemoryObject's */
        uint64_t size1 = S2E_RAM_OBJECT_SIZE - pageOffset;
        if(!writeMemory(address, buf, size1, addressType))
            return false;
        if(!writeMemory(address + size1, buf + size1, size - size1, addressType))
            return false;
    }
    return true;
}

bool S2EExecutionState::writeMemory8(uint64_t address,
                                     uint8_t value, AddressType addressType)
{
    return writeMemory(address, &value, 8, addressType);
}

bool S2EExecutionState::writeMemory16(uint64_t address,
                                     uint16_t value, AddressType addressType)
{
    return writeMemory(address, (uint8_t*) &value, 16, addressType);
}

bool S2EExecutionState::writeMemory32(uint64_t address,
                                      uint32_t value, AddressType addressType)
{
    return writeMemory(address, (uint8_t*) &value, 32, addressType);
}

bool S2EExecutionState::writeMemory64(uint64_t address,
                                     uint64_t value, AddressType addressType)
{
    return writeMemory(address, (uint8_t*) &value, 64, addressType);
}

namespace {
static int _lastSymbolicId = 0;
}

ref<Expr> S2EExecutionState::createSymbolicValue(
            Expr::Width width, const std::string& name)
{

    std::string sname = !name.empty() ? name : "symb_" + llvm::utostr(++_lastSymbolicId);

    const Array *array = new Array(sname, Expr::getMinBytesForWidth(width));

    //Add it to the set of symbolic expressions, to be able to generate
    //test cases later.
    //Dummy memory object
    MemoryObject *mo = new MemoryObject(0, Expr::getMinBytesForWidth(width), false, false, false, NULL);
    mo->setName(sname);

    symbolics.push_back(std::make_pair(mo, array));

    return  Expr::createTempRead(array, width);
}

std::vector<ref<Expr> > S2EExecutionState::createSymbolicArray(
            unsigned size, const std::string& name)
{
    std::string sname = !name.empty() ? name : "symb_" + llvm::utostr(++_lastSymbolicId);
    const Array *array = new Array(sname, size);

    UpdateList ul(array, 0);

    std::vector<ref<Expr> > result; result.reserve(size);
    for(unsigned i = 0; i < size; ++i) {
        result.push_back(ReadExpr::create(ul,
                    ConstantExpr::alloc(i,Expr::Int32)));
    }

    //Add it to the set of symbolic expressions, to be able to generate
    //test cases later.
    //Dummy memory object
    MemoryObject *mo = new MemoryObject(0, size, false, false, false, NULL);
    mo->setName(sname);

    symbolics.push_back(std::make_pair(mo, array));
    
    return result;
}

//Must be called right after the machine call instruction is executed.
//This function will reexecute the call but in symbolic mode
//XXX: remove circular references with executor?
void S2EExecutionState::undoCallAndJumpToSymbolic()
{
    if (g_s2e->getExecutor()->needToJumpToSymbolic(this)) {
        //Undo the call
        assert(getTb()->pcOfLastInstr);
        setSp(getSp() + sizeof(uint32_t));
        setPc(getTb()->pcOfLastInstr);
        g_s2e->getExecutor()->jumpToSymbolicCpp(this);
    }
}

void S2EExecutionState::dumpX86State(std::ostream &os) const
{

    os << "[State " << std::dec << m_stateID << "] CPU dump" << std::endl;
    os << "EAX=0x" << std::hex << readCpuRegister(offsetof(CPUState, regs[R_EAX]), klee::Expr::Int32) << std::endl;
    os << "EBX=0x" << readCpuRegister(offsetof(CPUState, regs[R_EBX]), klee::Expr::Int32) << std::endl;
    os << "ECX=0x" << readCpuRegister(offsetof(CPUState, regs[R_ECX]), klee::Expr::Int32) << std::endl;
    os << "EDX=0x" << readCpuRegister(offsetof(CPUState, regs[R_EDX]), klee::Expr::Int32) << std::endl;
    os << "ESI=0x" << readCpuRegister(offsetof(CPUState, regs[R_ESI]), klee::Expr::Int32) << std::endl;
    os << "EDI=0x" << readCpuRegister(offsetof(CPUState, regs[R_EDI]), klee::Expr::Int32) << std::endl;
    os << "EBP=0x" << readCpuRegister(offsetof(CPUState, regs[R_EBP]), klee::Expr::Int32) << std::endl;
    os << "ESP=0x" << readCpuRegister(offsetof(CPUState, regs[R_ESP]), klee::Expr::Int32) << std::endl;
    os << "EIP=0x" << readCpuState(offsetof(CPUState, eip), 32) << std::endl;
    os << "CR2=0x" << readCpuState(offsetof(CPUState, cr[2]), 32) << std::endl;
    os << "cc_op=0x" << readCpuRegister(offsetof(CPUState, cc_op), klee::Expr::Int32) << std::endl;
    os << "cc_src=0x" << readCpuRegister(offsetof(CPUState, cc_src), klee::Expr::Int32) << std::endl;
    os << "cc_dst=0x" << readCpuRegister(offsetof(CPUState, cc_dst), klee::Expr::Int32) << std::endl;
    os << "ES=0x" << readCpuState(offsetof(CPUState, segs[R_ES].selector), 32) << std::endl;
    //os << "ESi222=0x" << env->segs[R_ES]->name << std::endl;
    os << "CS=0x" << readCpuState(offsetof(CPUState, segs[R_CS].selector), 32) << std::endl;
    os << "SS=0x" << readCpuState(offsetof(CPUState, segs[R_SS].selector), 32) << std::endl;
    os << "DS=0x" << readCpuState(offsetof(CPUState, segs[R_DS].selector), 32) << std::endl;
    os << "FS=0x" << readCpuState(offsetof(CPUState, segs[R_FS].selector), 32) << std::endl;
    os << "GS=0x" << readCpuState(offsetof(CPUState, segs[R_GS].selector), 32) << std::endl;
    os << std::dec;
}

bool S2EExecutionState::merge(const ExecutionState &_b)
{
    assert(dynamic_cast<const S2EExecutionState*>(&_b));
    const S2EExecutionState& b = static_cast<const S2EExecutionState&>(_b);

    assert(!m_active && !b.m_active);

    std::ostream& s = g_s2e->getMessagesStream(this);

    if(DebugLogStateMerge)
        s << "Attempting merge with state " << b.getID() << std::endl;

    if(pc != b.pc) {
        if(DebugLogStateMerge)
            s << "merge failed: different pc" << std::endl;
        return false;
    }

    // XXX is it even possible for these to differ? does it matter? probably
    // implies difference in object states?
    if(symbolics != b.symbolics) {
        if(DebugLogStateMerge)
            s << "merge failed: different symbolics" << std::endl;
        return false;
    }

    {
        std::vector<StackFrame>::const_iterator itA = stack.begin();
        std::vector<StackFrame>::const_iterator itB = b.stack.begin();
        while (itA!=stack.end() && itB!=b.stack.end()) {
            // XXX vaargs?
            if(itA->caller!=itB->caller || itA->kf!=itB->kf) {
                if(DebugLogStateMerge)
                    s << "merge failed: different callstacks" << std::endl;
            }
          ++itA;
          ++itB;
        }
        if(itA!=stack.end() || itB!=b.stack.end()) {
            if(DebugLogStateMerge)
                s << "merge failed: different callstacks" << std::endl;
            return false;
        }
    }

    std::set< ref<Expr> > aConstraints(constraints.begin(), constraints.end());
    std::set< ref<Expr> > bConstraints(b.constraints.begin(),
                                       b.constraints.end());
    std::set< ref<Expr> > commonConstraints, aSuffix, bSuffix;
    std::set_intersection(aConstraints.begin(), aConstraints.end(),
                          bConstraints.begin(), bConstraints.end(),
                          std::inserter(commonConstraints, commonConstraints.begin()));
    std::set_difference(aConstraints.begin(), aConstraints.end(),
                        commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(aSuffix, aSuffix.end()));
    std::set_difference(bConstraints.begin(), bConstraints.end(),
                        commonConstraints.begin(), commonConstraints.end(),
                        std::inserter(bSuffix, bSuffix.end()));
    if(DebugLogStateMerge) {
        s << "\tconstraint prefix: [";
        for(std::set< ref<Expr> >::iterator it = commonConstraints.begin(),
                        ie = commonConstraints.end(); it != ie; ++it)
            s << *it << ", ";
        s << "]\n";
        s << "\tA suffix: [";
        for(std::set< ref<Expr> >::iterator it = aSuffix.begin(),
                        ie = aSuffix.end(); it != ie; ++it)
            s << *it << ", ";
        s << "]\n";
        s << "\tB suffix: [";
        for(std::set< ref<Expr> >::iterator it = bSuffix.begin(),
                        ie = bSuffix.end(); it != ie; ++it)
        s << *it << ", ";
        s << "]" << std::endl;
    }

    /* Check CPUState */
    {
        uint8_t* cpuStateA = m_cpuSystemObject->getConcreteStore() - CPU_OFFSET(eip);
        uint8_t* cpuStateB = b.m_cpuSystemObject->getConcreteStore() - CPU_OFFSET(eip);
        if(memcmp(cpuStateA + CPU_OFFSET(eip), cpuStateB + CPU_OFFSET(eip),
                  CPU_OFFSET(current_tb) - CPU_OFFSET(eip))) {
            if(DebugLogStateMerge)
                s << "merge failed: different concrete cpu state" << std::endl;
            return false;
        }
    }

    // We cannot merge if addresses would resolve differently in the
    // states. This means:
    //
    // 1. Any objects created since the branch in either object must
    // have been free'd.
    //
    // 2. We cannot have free'd any pre-existing object in one state
    // and not the other

    //if(DebugLogStateMerge) {
    //    s << "\tchecking object states\n";
    //    s << "A: " << addressSpace.objects << "\n";
    //    s << "B: " << b.addressSpace.objects << "\n";
    //}

    std::set<const MemoryObject*> mutated;
    MemoryMap::iterator ai = addressSpace.objects.begin();
    MemoryMap::iterator bi = b.addressSpace.objects.begin();
    MemoryMap::iterator ae = addressSpace.objects.end();
    MemoryMap::iterator be = b.addressSpace.objects.end();
    for(; ai!=ae && bi!=be; ++ai, ++bi) {
        if (ai->first != bi->first) {
            if (DebugLogStateMerge) {
                if (ai->first < bi->first) {
                    s << "\t\tB misses binding for: " << ai->first->id << "\n";
                } else {
                    s << "\t\tA misses binding for: " << bi->first->id << "\n";
                }
            }
            if(DebugLogStateMerge)
                s << "merge failed: different callstacks" << std::endl;
            return false;
        }
        if(ai->second != bi->second && !ai->first->isValueIgnored &&
                    ai->first != m_cpuSystemState && ai->first != m_dirtyMask) {
            const MemoryObject *mo = ai->first;
            if(DebugLogStateMerge)
                s << "\t\tmutated: " << mo->id << " (" << mo->name << ")\n";
            if(mo->isSharedConcrete) {
                if(DebugLogStateMerge)
                    s << "merge failed: different shared-concrete objects "
                      << std::endl;
                return false;
            }
            mutated.insert(mo);
        }
    }
    if(ai!=ae || bi!=be) {
        if(DebugLogStateMerge)
            s << "merge failed: different address maps" << std::endl;
        return false;
    }

    // Create state predicates
    ref<Expr> inA = ConstantExpr::alloc(1, Expr::Bool);
    ref<Expr> inB = ConstantExpr::alloc(1, Expr::Bool);
    for(std::set< ref<Expr> >::iterator it = aSuffix.begin(),
                 ie = aSuffix.end(); it != ie; ++it)
        inA = AndExpr::create(inA, *it);
    for(std::set< ref<Expr> >::iterator it = bSuffix.begin(),
                 ie = bSuffix.end(); it != ie; ++it)
        inB = AndExpr::create(inB, *it);

    // XXX should we have a preference as to which predicate to use?
    // it seems like it can make a difference, even though logically
    // they must contradict each other and so inA => !inB

    // merge LLVM stacks

    int selectCountStack = 0, selectCountMem = 0;

    std::vector<StackFrame>::iterator itA = stack.begin();
    std::vector<StackFrame>::const_iterator itB = b.stack.begin();
    for(; itA!=stack.end(); ++itA, ++itB) {
        StackFrame &af = *itA;
        const StackFrame &bf = *itB;
        for(unsigned i=0; i<af.kf->numRegisters; i++) {
            ref<Expr> &av = af.locals[i].value;
            const ref<Expr> &bv = bf.locals[i].value;
            if(av.isNull() || bv.isNull()) {
                // if one is null then by implication (we are at same pc)
                // we cannot reuse this local, so just ignore
            } else {
                if(av != bv) {
                    av = SelectExpr::create(inA, av, bv);
                    selectCountStack += 1;
                }
            }
        }
    }

    if(DebugLogStateMerge)
        s << "\t\tcreated " << selectCountStack << " select expressions on the stack\n";

    for(std::set<const MemoryObject*>::iterator it = mutated.begin(),
                    ie = mutated.end(); it != ie; ++it) {
        const MemoryObject *mo = *it;
        const ObjectState *os = addressSpace.findObject(mo);
        const ObjectState *otherOS = b.addressSpace.findObject(mo);
        assert(os && !os->readOnly &&
               "objects mutated but not writable in merging state");
        assert(otherOS);

        ObjectState *wos = addressSpace.getWriteable(mo, os);
        for (unsigned i=0; i<mo->size; i++) {
            ref<Expr> av = wos->read8(i);
            ref<Expr> bv = otherOS->read8(i);
            if(av != bv) {
                wos->write(i, SelectExpr::create(inA, av, bv));
                selectCountMem += 1;
            }
        }
    }

    if(DebugLogStateMerge)
        s << "\t\tcreated " << selectCountMem << " select expressions in memory\n";

    constraints = ConstraintManager();
    for(std::set< ref<Expr> >::iterator it = commonConstraints.begin(),
                ie = commonConstraints.end(); it != ie; ++it)
        addConstraint(*it);

    addConstraint(OrExpr::create(inA, inB));

    // Merge dirty mask by clearing bits that differ. Clearning bits in
    // dirty mask can only affect performance but not correcntess.
    // NOTE: this requires flushing TLB
    {
        const ObjectState* os = addressSpace.findObject(m_dirtyMask);
        ObjectState* wos = addressSpace.getWriteable(m_dirtyMask, os);
        uint8_t* dirtyMaskA = wos->getConcreteStore();
        const uint8_t* dirtyMaskB = b.addressSpace.findObject(m_dirtyMask)->getConcreteStore();

        for(unsigned i = 0; i < m_dirtyMask->size; ++i) {
            if(dirtyMaskA[i] != dirtyMaskB[i])
                dirtyMaskA[i] = 0;
        }
    }

    // Flush TLB
    {
        CPUState* cpu = (CPUState*) (m_cpuSystemObject->getConcreteStore() - CPU_OFFSET(eip));
        cpu->current_tb = NULL;

        for (int mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
            for(int i = 0; i < CPU_TLB_SIZE; i++)
                cpu->tlb_table[mmu_idx][i] = s_cputlb_empty_entry;
            for(int i = 0; i < CPU_S2E_TLB_SIZE; i++)
                cpu->s2e_tlb_table[mmu_idx][i].objectState = 0;
        }

        memset (cpu->tb_jmp_cache, 0, TB_JMP_CACHE_SIZE * sizeof (void *));
    }

    return true;
}

CPUState *S2EExecutionState::getConcreteCpuState() const
{
    return (CPUState*) (m_cpuSystemState->address - CPU_OFFSET(eip));
}

#ifdef __MHHUANG_MEASURE_TIME__
void S2EExecutionState::printAllStat() {
    std::map<uint32_t, klee::ProcStat*>::iterator pIt = allProcStat.begin();
    for(;pIt != allProcStat.end(); pIt++) {
        g_s2e->getWarningsStream(this) << "Process " << std::hex << pIt->first << " :" << std::endl;
        g_s2e->getWarningsStream(this) << "NumBr: " << pIt->second->numBr << 
                                          ", KnownGuestBr: " << pIt->second->numKnownGuestBr << 
                                          ", UnknownGuestBr: " << pIt->second->numUnknownGuestBr << 
                                          ", KnownHelperBr: " << pIt->second->numKnownHelperBr << 
                                          ", UnknownHelperBr: " << pIt->second->numUnknownHelperBr << 
                                          std::endl;
        g_s2e->getWarningsStream(this) << "NumEvaluate: " << pIt->second->numEvaluate << 
                                          ", tEvaluate: " << ((float)(pIt->second->tEvaluate))/CLOCKS_PER_SEC << 
                                          std::endl;
        g_s2e->getWarningsStream(this) << "NumAddCon: " << pIt->second->numAddCon << 
                                          ", tAddCon: " << ((float)(pIt->second->tAddCon))/CLOCKS_PER_SEC << 
                                          std::endl;
        g_s2e->getWarningsStream(this) << "NumMustBeTrue: " << pIt->second->numMustBeTrue << 
                                          ", tMustBeTrue: " << ((float)(pIt->second->tMustBeTrue))/CLOCKS_PER_SEC << 
                                          std::endl;
        g_s2e->getWarningsStream(this) << "NumGetValue: " << pIt->second->numGetValue << 
                                          ", tGetValue: " << ((float)(pIt->second->tGetValue))/CLOCKS_PER_SEC << 
                                          std::endl;
        g_s2e->getWarningsStream(this) << "tKlee: " <<  ((float)(pIt->second->tKlee))/CLOCKS_PER_SEC << 
                                          ", tComputeCC: " <<  ((float)(pIt->second->tComputeCC))/CLOCKS_PER_SEC << 
                                          ", tHelper: " << ((float)(pIt->second->tHelper))/CLOCKS_PER_SEC << 
                                          ", tCallExternal: " << ((float)(pIt->second->tCallExternal))/CLOCKS_PER_SEC << 
                                          std::endl;
        g_s2e->getWarningsStream(this) << "Sym-exec icount: " << pIt->second->symICount << 
                                          ", con-exec icount: " << pIt->second->conICount << std::endl;
        
        std::map<uint32_t, uint32_t>::iterator bIt = pIt->second->allKnownBranchStat.begin();
        for(; bIt != pIt->second->allKnownBranchStat.end(); bIt++) {
            g_s2e->getWarningsStream(this) << "KnownBranch at " << std::hex << bIt->first << " takes " << std::dec << bIt->second << " times" << std::endl;
        }

        bIt = pIt->second->allUnknownBranchStat.begin();
        for(; bIt != pIt->second->allUnknownBranchStat.end(); bIt++) {
            g_s2e->getWarningsStream(this) << "UnknownBranch at " << std::hex << bIt->first << " takes " << std::dec << bIt->second << " times" << std::endl;
        }

        std::map<std::string, klee::HelperStat*>::iterator hIt = pIt->second->allHelperStat.begin();
        for(; hIt != pIt->second->allHelperStat.end(); hIt++) {
            g_s2e->getWarningsStream(this) << "Helper " << hIt->first << 
                                              ":\ttExec: " <<  ((float)(hIt->second->tExec))/CLOCKS_PER_SEC << 
                                              ":\ttComputeCC: " <<  ((float)(hIt->second->tComputeCC))/CLOCKS_PER_SEC << 
                                              ",\tKnown: " <<  hIt->second->numKnownBr << 
                                              ",\tUnknown: " << hIt->second->numUnknownBr << 
                                              std::endl;
        }
    }

    g_s2e->getWarningsStream(this) << "Number of constraints: " << constraints.constraints.size() << std::endl;
}
#endif

} // namespace s2e

/******************************/
/* Functions called from QEMU */

extern "C" {

S2EExecutionState* g_s2e_state = NULL;

void s2e_dump_state()
{
    g_s2e_state->dumpX86State(g_s2e->getDebugStream());
}

} // extern "C"

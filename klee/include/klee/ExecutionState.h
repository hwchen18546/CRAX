//===-- ExecutionState.h ----------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXECUTIONSTATE_H
#define KLEE_EXECUTIONSTATE_H

#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/TreeStream.h"

// FIXME: We do not want to be exposing these? :(
#include "../../lib/Core/AddressSpace.h"
#include "klee/Internal/Module/KInstIterator.h"

#include "klee/Solver.h"
#include "../../lib/Core/TimingSolver.h"

#include <map>
#include <set>
#include <vector>

namespace klee {
  class Array;
  class CallPathNode;
  class Cell;
  class KFunction;
  class KInstruction;
  class MemoryObject;
  class PTreeNode;
  class InstructionInfo;

std::ostream &operator<<(std::ostream &os, const MemoryMap &mm);

struct StackFrame {
  KInstIterator caller;
  KFunction *kf;
  CallPathNode *callPathNode;

  std::vector<const MemoryObject*> allocas;
  Cell *locals;

  /// Minimum distance to an uncovered instruction once the function
  /// returns. This is not a good place for this but is used to
  /// quickly compute the context sensitive minimum distance to an
  /// uncovered instruction. This value is updated by the StatsTracker
  /// periodically.
  unsigned minDistToUncoveredOnReturn;

  // For vararg functions: arguments not passed via parameter are
  // stored (packed tightly) in a local (alloca) memory object. This
  // is setup to match the way the front-end generates vaarg code (it
  // does not pass vaarg through as expected). VACopy is lowered inside
  // of intrinsic lowering.
  MemoryObject *varargs;

  StackFrame(KInstIterator caller, KFunction *kf);
  StackFrame(const StackFrame &s);
  ~StackFrame();
};

#ifdef __MHHUANG_MEASURE_TIME__
class HelperStat {
public:
    clock_t tExec;
    clock_t tComputeCC;
    uint64_t numKnownBr;
    uint64_t numUnknownBr;

    HelperStat() {
        tExec = 0;
        tComputeCC = 0;
        numKnownBr = 0;
        numUnknownBr = 0;
    }
};

class ProcStat {
public:
    clock_t tEvaluate, tMustBeTrue, tGetValue, tAddCon, tLastEvaluate, tLastAddCon, tKlee, tHelper, tCallExternal, tComputeCC;
    uint64_t numBr, numKnownGuestBr, numUnknownGuestBr, numKnownHelperBr, numUnknownHelperBr, numEvaluate, numMustBeTrue, numGetValue, numAddCon, conICount, symICount;
    HelperStat *helperCC;
    std::map<std::string, HelperStat*> allHelperStat;
    std::map<uint32_t, uint32_t> allKnownBranchStat;    /* map from eip to calling times */
    std::map<uint32_t, uint32_t> allUnknownBranchStat;  /* map from eip to calling times */

    ProcStat() {
        tEvaluate = 0;
        tMustBeTrue = 0;
        tGetValue = 0;
        tAddCon = 0;
        tLastEvaluate = 0;
        tLastAddCon = 0;
        tKlee = 0;
        tHelper = 0;
        tCallExternal = 0;
        tComputeCC = 0;
        numBr = 0;
        numKnownGuestBr = 0;
        numUnknownGuestBr = 0;
        numKnownHelperBr = 0;
        numUnknownHelperBr = 0;
        numEvaluate = 0;
        numMustBeTrue = 0;
        numGetValue = 0;
        numAddCon = 0;
        conICount = 0;
        symICount = 0;
        helperCC = NULL;
    }
};
#endif

class ExecutionState {
  friend class AddressSpace;

public:
  typedef std::vector<StackFrame> stack_ty;

private:
  // unsupported, use copy constructor
  ExecutionState &operator=(const ExecutionState&); 
  std::map< std::string, std::string > fnAliases;

public:
  mutable ConstraintManager constraints;

  bool fakeState;
  // Are we currently underconstrained?  Hack: value is size to make fake
  // objects.
  unsigned underConstrained;
  unsigned depth;
  
  // pc - pointer to current instruction stream
  KInstIterator pc, prevPC;
  stack_ty stack;
  mutable double queryCost;
  double weight;
  AddressSpace addressSpace;
  TreeOStream pathOS, symPathOS;
  unsigned instsSinceCovNew;
  bool coveredNew;

  /// Disables forking, set by user code.
  bool forkDisabled;

  std::map<const std::string*, std::set<unsigned> > coveredLines;
  PTreeNode *ptreeNode;

  /// ordered list of symbolics: used to generate test cases. 
  //
  // FIXME: Move to a shared list structure (not critical).
  std::vector< std::pair<const MemoryObject*, const Array*> > symbolics;

  // Used by the checkpoint/rollback methods for fake objects.
  // FIXME: not freeing things on branch deletion.
  MemoryMap shadowObjects;

  unsigned incomingBBIndex;

  std::string getFnAlias(std::string fn);
  void addFnAlias(std::string old_fn, std::string new_fn);
  void removeFnAlias(std::string fn);

#ifdef __MHHUANG_MEASURE_TIME__
  /* The mutable keyword enable us to change the value of those fields in functions with 
     const ExecutionState parameter */

  /* Map env->cr[3] value to ProcStat */
  mutable std::map<uint32_t, ProcStat*> allProcStat;
  mutable std::map<uint32_t, ProcStat*>::iterator currentProcStat;
  mutable uint32_t lastCr3, lastStackSize;
  mutable ProcStat *pCurProcStat;
  mutable HelperStat *pCurHelperStat;
  mutable HelperStat *pHelperCC;
  mutable HelperStat *pHelperCCCaller;
#endif

#if defined(__MHHUANG_EBP_EXPLOIT__)
  bool inHelper;
#endif

  bool isConcolicMode;

  uint32_t *eip;
  uint32_t *ebp;
  uint32_t *esp;
  uint32_t *cr3;  /* -mhhuang- used to trace guest OS process */

private:
  void initialize();

  ExecutionState() : fakeState(false), underConstrained(0),
                     addressSpace(this), ptreeNode(0) {
    initialize();
  }

protected:
  virtual ExecutionState* clone();
  virtual void addressSpaceChange(const MemoryObject *mo,
                                  const ObjectState *oldState,
                                  ObjectState *newState);

public:
  ExecutionState(KFunction *kf);

  // XXX total hack, just used to make a state so solver can
  // use on structure
  ExecutionState(const std::vector<ref<Expr> > &assumptions);

  virtual ~ExecutionState();
  
  ExecutionState *branch();

  void pushFrame(KInstIterator caller, KFunction *kf);
  void popFrame();

  void addSymbolic(const MemoryObject *mo, const Array *array) { 
    symbolics.push_back(std::make_pair(mo, array));
  }

  /* An ugly hack to let TimingSolver use S2EExecutionState's field */
  virtual bool evaluate(TimingSolver &solver, ref<Expr> expr, Solver::Validity &result) const;
  virtual bool mustBeTrue(TimingSolver &solver, ref<Expr> expr, bool &result) const;
  virtual bool mustBeFalse(TimingSolver &solver, ref<Expr> expr, bool &result) const;
  virtual bool mayBeTrue(TimingSolver &solver, ref<Expr> expr, bool &result) const;
  virtual bool mayBeFalse(TimingSolver &solver, ref<Expr> expr, bool &result) const;
  virtual bool getValue(TimingSolver &solver, ref<Expr> expr, ref<ConstantExpr> &result) const;
  virtual bool getInitialValues(TimingSolver &solver, const std::vector<const Array*> &objects, 
                std::vector< std::vector<unsigned char> > &result) const;

  /* An ugly hack to let Executor::getSymbolicSolution works */
  virtual ExecutionState* getClone() const;

  virtual void addConstraint(ref<Expr> e) const;

  virtual bool merge(const ExecutionState &b);
};

}

#endif

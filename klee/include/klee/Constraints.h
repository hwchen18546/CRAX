//===-- Constraints.h -------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_CONSTRAINTS_H
#define KLEE_CONSTRAINTS_H

#include "klee/Expr.h"

// FIXME: Currently we use ConstraintManager for two things: to pass
// sets of constraints around, and to optimize constraints. We should
// move the first usage into a separate data structure
// (ConstraintSet?) which ConstraintManager could embed if it likes.
namespace klee {

class ExprVisitor;
  
class ConstraintManager {
private:
  bool needReplaceByPermanentCons;
  bool inConcolicEvalStage;
  bool inPermanentEvalStage;
#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
  bool inEmptyEvalStage;
#endif

public:
  typedef std::vector< ref<Expr> > constraints_ty;
  typedef constraints_ty::iterator iterator;
  typedef constraints_ty::const_iterator const_iterator;

  ConstraintManager()
  {
      needReplaceByPermanentCons = false;
      inConcolicEvalStage = false;
      inPermanentEvalStage = false;
#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
      inEmptyEvalStage = false;
#endif
  }

  // create from constraints with no optimization
  explicit
  ConstraintManager(const std::vector< ref<Expr> > &_constraints) :
      constraints(_constraints),
      tempConstraints(_constraints)
  {
      needReplaceByPermanentCons = false;
      inConcolicEvalStage = false;
      inPermanentEvalStage = false;
#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
      inEmptyEvalStage = false;
#endif
  }

  ConstraintManager(const ConstraintManager &cs) : 
      constraints(cs.constraints),
      concolicConstraints(cs.concolicConstraints),
      tempConstraints(cs.tempConstraints),
      permanentConstraints(cs.permanentConstraints)
  {
      needReplaceByPermanentCons = cs.needReplaceByPermanentCons;
      inConcolicEvalStage = cs.inConcolicEvalStage;
      inPermanentEvalStage = cs.inPermanentEvalStage;
#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
      inEmptyEvalStage = cs.inEmptyEvalStage;
#endif
  }

  typedef std::vector< ref<Expr> >::const_iterator constraint_iterator;

  // given a constraint which is known to be valid, attempt to 
  // simplify the existing constraint set
  void simplifyForValidConstraint(ref<Expr> e);

  ref<Expr> simplifyExpr(ref<Expr> e) const;

  void cAddConstraint(ref<Expr> e);
 
  bool empty() const {
    assert(readyToUse());
    return constraints.empty();
  }

  ref<Expr> back() const {
    assert(readyToUse());
    return constraints.back();
  }

  constraint_iterator begin() const {
    assert(readyToUse());
    return constraints.begin();
  }

  constraint_iterator end() const {
    assert(readyToUse());
    return constraints.end();
  }

  size_t size() const {
    assert(readyToUse());
    return constraints.size();
  }

  void pop_back()
  {
    assert(readyToUse());
    if(!empty())
      constraints.pop_back();
  }

  iterator erase(int num)
  {
    assert(readyToUse());
    return constraints.erase(constraints.begin(), constraints.begin()+num);
  }

  void addConcolicConstraint(ref<Expr> e)
  {
    concolicConstraints.push_back(e);
  }

  void addPermanentConstraintAndClearTempConstraints(ref<Expr> e);

  void addTempConstraint(ref<Expr> e);
  void clearTempConstraints();
  std::vector<ref<Expr> > getTempConstraints();
  void setTempConstraints(std::vector<ref<Expr> > tempCons);

  void startSymbolicEvaluate();
  void endSymbolicEvaluate();
  void startConcolicEvaluate();
  void endConcolicEvaluate();
  void startPermanentEvaluate();
  void endPermanentEvaluate();
#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
  void startEmptyEvaluate();
  void endEmptyEvaluate();
#endif

  bool readyToUse() const { 
      return !needReplaceByPermanentCons || 
      inConcolicEvalStage ||
#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
      inEmptyEvalStage ||
#endif
      inPermanentEvalStage; 
  }

  bool operator==(const ConstraintManager &other) const {
    return constraints == other.constraints;
  }

  /* Added by mhhuang */
  int saveAllConcolicConstraints();
  int saveAllConstraints(int id = 0);

private:
  std::vector<ref<Expr> > constraints;
  std::vector<ref<Expr> > concolicConstraints;
  std::vector<ref<Expr> > tempConstraints;
  std::vector<ref<Expr> > permanentConstraints;
#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
  std::vector<ref<Expr> > emptyConstraints;
#endif

  // returns true iff the constraints were modified
  bool rewriteConstraints(ExprVisitor &visitor);

  void addConstraintInternal(ref<Expr> e);
};

}

#endif /* KLEE_CONSTRAINTS_H */

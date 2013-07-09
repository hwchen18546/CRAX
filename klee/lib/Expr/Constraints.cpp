//===-- Constraints.cpp ---------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Constraints.h"

#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprVisitor.h"

#include <iostream>
#include <map>

using namespace klee;

class ExprReplaceVisitor : public ExprVisitor {
private:
  ref<Expr> src, dst;

public:
  ExprReplaceVisitor(ref<Expr> _src, ref<Expr> _dst) : src(_src), dst(_dst) {}

  Action visitExpr(const Expr &e) {
    if (e == *src.get()) {
      return Action::changeTo(dst);
    } else {
      return Action::doChildren();
    }
  }

  Action visitExprPost(const Expr &e) {
    if (e == *src.get()) {
      return Action::changeTo(dst);
    } else {
      return Action::doChildren();
    }
  }
};

class ExprReplaceVisitor2 : public ExprVisitor {
private:
  const std::map< ref<Expr>, ref<Expr> > &replacements;

public:
  ExprReplaceVisitor2(const std::map< ref<Expr>, ref<Expr> > &_replacements) 
    : ExprVisitor(true),
      replacements(_replacements) {}

  Action visitExprPost(const Expr &e) {
    std::map< ref<Expr>, ref<Expr> >::const_iterator it =
      replacements.find(ref<Expr>((Expr*) &e));
    if (it!=replacements.end()) {
      return Action::changeTo(it->second);
    } else {
      return Action::doChildren();
    }
  }
};

bool ConstraintManager::rewriteConstraints(ExprVisitor &visitor) {
  ConstraintManager::constraints_ty old;
  bool changed = false;
  
  constraints.swap(old);
  for (ConstraintManager::constraints_ty::iterator 
         it = old.begin(), ie = old.end(); it != ie; ++it) {
    ref<Expr> &ce = *it;
    ref<Expr> e = visitor.visit(ce);
    if (e!=ce) {
      addConstraintInternal(e); // enable further reductions
      changed = true;
    } else {
      constraints.push_back(ce);
    }
  }
  return changed;
}

void ConstraintManager::simplifyForValidConstraint(ref<Expr> e) {
  // XXX 
}

ref<Expr> ConstraintManager::simplifyExpr(ref<Expr> e) const {
  if (isa<ConstantExpr>(e))
    return e;

#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
  ConstraintManager *cm = const_cast<ConstraintManager*>(this);
  static std::vector<ref<Expr> > empty;
  cm->constraints.swap(empty);
#endif

  std::map< ref<Expr>, ref<Expr> > equalities;
  for (ConstraintManager::constraints_ty::const_iterator 
         it = constraints.begin(), ie = constraints.end(); it != ie; ++it) {
    if (const EqExpr *ee = dyn_cast<EqExpr>(*it)) {
      if (isa<ConstantExpr>(ee->left)) {
        equalities.insert(std::make_pair(ee->right,
                                         ee->left));
      } else {
        equalities.insert(std::make_pair(*it,
                                         ConstantExpr::alloc(1, Expr::Bool)));
      }
    } else {
      equalities.insert(std::make_pair(*it,
                                       ConstantExpr::alloc(1, Expr::Bool)));
    }
  }

  ref<Expr> res = ExprReplaceVisitor2(equalities).visit(e);

#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
  cm->constraints.swap(empty);
#endif

  return res;
}

void ConstraintManager::addConstraintInternal(ref<Expr> e) {
  // rewrite any known equalities 

  // XXX should profile the effects of this and the overhead.
  // traversing the constraints looking for equalities is hardly the
  // slowest thing we do, but it is probably nicer to have a
  // ConstraintSet ADT which efficiently remembers obvious patterns
  // (byte-constant comparison).
  switch (e->getKind()) {
  case Expr::Constant:
    break;
    
  // split to enable finer grained independence and other optimizations
  case Expr::And: {
    BinaryExpr *be = cast<BinaryExpr>(e);
    addConstraintInternal(be->left);
    addConstraintInternal(be->right);
    break;
  }

  case Expr::Eq: {
    BinaryExpr *be = cast<BinaryExpr>(e);
    if (isa<ConstantExpr>(be->left)) {
      ExprReplaceVisitor visitor(be->right, be->left);
      rewriteConstraints(visitor);
    }
    constraints.push_back(e);
    break;
  }
    
  default:
    constraints.push_back(e);
    break;
  }
}

void ConstraintManager::cAddConstraint(ref<Expr> e) {
  e = simplifyExpr(e);
  addConstraintInternal(e);
}

void ConstraintManager::addPermanentConstraintAndClearTempConstraints(ref<Expr> e) {
    clearTempConstraints();

    constraints.swap(permanentConstraints);
    cAddConstraint(e);
    constraints.swap(permanentConstraints);

    cAddConstraint(e);
}

void ConstraintManager::addTempConstraint(ref<Expr> e) {
    //if(needReplaceByPermanentCons) {
    //    constraints = permanentConstraints;
    //    needReplaceByPermanentCons = false;
    //}

    cAddConstraint(e);
    tempConstraints.push_back(e);
}

void ConstraintManager::clearTempConstraints() {
    //needReplaceByPermanentCons = true;
    constraints = permanentConstraints;
    tempConstraints.clear();
}

std::vector<ref<Expr> > ConstraintManager::getTempConstraints() {
    return tempConstraints;
}

void ConstraintManager::setTempConstraints(std::vector<ref<Expr> > tempCons) {
    clearTempConstraints();

    std::vector<ref<Expr> >::iterator it;
    for(it=tempCons.begin(); it!=tempCons.end(); it++) {
        addTempConstraint(*it);
    }
}

void ConstraintManager::startSymbolicEvaluate() {
    //if(needReplaceByPermanentCons) {
    //    constraints = permanentConstraints;
    //    needReplaceByPermanentCons = false;
    //}
}

void ConstraintManager::endSymbolicEvaluate() {
}

void ConstraintManager::startConcolicEvaluate() {
    assert(inPermanentEvalStage == false);

    constraints.swap(concolicConstraints);
    inConcolicEvalStage = true;
}

void ConstraintManager::endConcolicEvaluate() {
    constraints.swap(concolicConstraints);
    inConcolicEvalStage = false;
}

void ConstraintManager::startPermanentEvaluate() {
    assert(inConcolicEvalStage == false);

    constraints.swap(permanentConstraints);
    inPermanentEvalStage = true;
}

void ConstraintManager::endPermanentEvaluate() {
    constraints.swap(permanentConstraints);
    inPermanentEvalStage = false;
}

#ifdef __MHHUANG_REDUCE_SIMPLIFY_EXPR__
void ConstraintManager::startEmptyEvaluate() {
    constraints.swap(emptyConstraints);
    inEmptyEvalStage = true;
}

void ConstraintManager::endEmptyEvaluate() {
    constraints.swap(emptyConstraints);
    inEmptyEvalStage = false;
}
#endif

//#ifdef __MHHUANG_GDB__
/* mhhuang */
#include <iostream>
#include <fstream>
#include <sstream>

/* mhhuang added function, only used in gdb */
int ConstraintManager::saveAllConcolicConstraints()
{
    std::ofstream fs;
    fs.open("/home/mhhuang/concolicconstraints");

    std::vector< ref<Expr> >::iterator it = concolicConstraints.begin(), e = concolicConstraints.end();

    for(; it!=e; it++) {
        Expr* ex = dyn_cast<Expr>((*it).get());
        fs << *ex;
        fs << "\n";
    }

    fs.close();
    return 1;
}

/* mhhuang added function, only used in gdb */
int ConstraintManager::saveAllConstraints(int id)
{
    std::ostringstream oss;
    oss << "/home/mhhuang/constraints_" << id;

    std::ofstream fs;
    fs.open(oss.str().c_str());

    std::vector< ref<Expr> >::iterator it = constraints.begin(), e = constraints.end();

    for(; it!=e; it++) {
        Expr* ex = dyn_cast<Expr>((*it).get());
        fs << *ex;
        fs << "\n";
    }

    fs.close();
    return 1;
}
//#endif


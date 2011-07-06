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
public:
  typedef std::vector< ref<Expr> > constraints_ty;
  typedef constraints_ty::iterator iterator;
  typedef constraints_ty::const_iterator const_iterator;


  ConstraintManager():concolic_constraints(ConstantExpr::create(0x1,Expr::Bool)),concolicSize(0) {}

  // create from constraints with no optimization
  explicit
  ConstraintManager(const std::vector< ref<Expr> > &_constraints) :
    constraints(_constraints),concolic_constraints(ConstantExpr::create(0x1,Expr::Bool)),concolicSize(0) {}

  ConstraintManager(const ConstraintManager &cs) : constraints(cs.constraints),concolic_constraints(cs.concolic_constraints),concolicSize(cs.concolicSize) {}

  typedef std::vector< ref<Expr> >::const_iterator constraint_iterator;

  // given a constraint which is known to be valid, attempt to 
  // simplify the existing constraint set
  void simplifyForValidConstraint(ref<Expr> e);

  ref<Expr> simplifyExpr(ref<Expr> e) const;

  void addConstraint(ref<Expr> e); // type:1(conoclic), type:2(all)
  
  bool empty() const {
    return constraints.empty();
  }
  ref<Expr> back() const {
    return constraints.back();
  }
  constraint_iterator begin() const {
    return constraints.begin();
  }
  constraint_iterator end() const {
    return constraints.end();
  }
  size_t size() const {
    return constraints.size();
  }

  void pop_back()
  {
    if(!empty())
      constraints.pop_back();
  }

  iterator erase(int num)
  {
    return constraints.erase(constraints.begin(), constraints.begin()+num);
  }

  void setConcolicSize(uint32_t num)
  {
    concolicSize = num;
  }

  uint32_t getConcolicSize()
  {
    return concolicSize;
  }
  
  void addConcolicConstraints(ref<Expr> e)
  {
    concolic_constraints = AndExpr::create(concolic_constraints, e);
  }

  ref<Expr> getConcolicConstraints()
  {
    return concolic_constraints;
  }

  std::vector< ref<Expr> > getConstraints()
  {
    return constraints;
  }

  bool operator==(const ConstraintManager &other) const {
    return constraints == other.constraints;
  }

  
private:
//public:
  std::vector< ref<Expr> > constraints;
  //std::vector< ref<Expr> > concolic_constraints;
  //std::vector< ref<Expr> > all_constraints;
  ref<Expr> concolic_constraints;
  uint32_t concolicSize;

  // returns true iff the constraints were modified
  bool rewriteConstraints(ExprVisitor &visitor);

  void addConstraintInternal(ref<Expr> e);
};

}

#endif /* KLEE_CONSTRAINTS_H */

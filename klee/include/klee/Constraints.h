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


  ConstraintManager():/*concolic_constraints(ConstantExpr::create(0x1,Expr::Bool)),*/noZero_constraints(ConstantExpr::create(0x1,Expr::Bool)) {}

  // create from constraints with no optimization
  explicit
  ConstraintManager(const std::vector< ref<Expr> > &_constraints) :
    constraints(_constraints)/*,concolic_constraints(ConstantExpr::create(0x1,Expr::Bool))*/, noZero_constraints(ConstantExpr::create(0x1,Expr::Bool)) {}

  ConstraintManager(const ConstraintManager &cs) : constraints(cs.constraints),concolic_constraints(cs.concolic_constraints), noZero_constraints(cs.noZero_constraints) {}

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
/*
  void setConcolicSize(uint32_t num)
  {
    concolicSize = num;
  }

  uint32_t getConcolicSize()
  {
    return concolicSize;
  }
*/  
  void addConcolicConstraints(ref<Expr> e)
  {
    concolic_constraints.push_back(e);
    //concolic_constraints = AndExpr::create(concolic_constraints, e);
  }

  void addNoZeroConstraints(ref<Expr> e)
  {
    noZero_constraints = AndExpr::create(noZero_constraints, e);
  }

  ref<Expr> getConcolicConstraints()
  {
    ref<Expr> temp = ConstantExpr::create(0x1,Expr::Bool);

    std::vector< ref<Expr> >::iterator it;
    for(it=concolic_constraints.begin() ; it!=concolic_constraints.end() ; it++)
    {
      temp = AndExpr::create(temp, *it);
    }
  
    return temp;
    //return concolic_constraints;
  }

  ref<Expr> getNoZeroConstraints()
  {
    return noZero_constraints;
  }

  std::vector< ref<Expr> > getConstraints()
  {
    return constraints;
  }
/*
  std::vector< ref<Expr> > getConcolicVector()
  {
    return concolic_constraints;
  }
*/
  bool operator==(const ConstraintManager &other) const {
    return constraints == other.constraints;
  }
/*
  void backupConstraints()
  {
    constraints_backup.assign(constraints.begin(), constraints.end());
  }

  void restoreConstraints()
  {
    //constraints.assign(constraints_backup.begin(), constraints_backup.end());
    constraints.swap(constraints_backup);
  }
*/
  void swapConstraints()
  {
    constraints.swap(concolic_constraints);
  }

  bool isConcolicEmpty()
  {
    return concolic_constraints.empty();
  }
  
private:
//public:
  std::vector< ref<Expr> > constraints;
  //std::vector< ref<Expr> > constraints_backup;
public:
  std::vector< ref<Expr> > concolic_constraints;
  //std::vector< ref<Expr> > all_constraints;
  //ref<Expr> concolic_constraints;
  ref<Expr> noZero_constraints;
  //uint32_t concolicSize;

  // returns true iff the constraints were modified
  bool rewriteConstraints(ExprVisitor &visitor);

  void addConstraintInternal(ref<Expr> e);
};

}

#endif /* KLEE_CONSTRAINTS_H */

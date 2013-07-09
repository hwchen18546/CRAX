//===-- TimingSolver.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "TimingSolver.h"

#include "klee/ExecutionState.h"
#include "klee/Solver.h"
#include "klee/Statistics.h"

#include "klee/CoreStats.h"

#include "llvm/System/Process.h"

using namespace klee;
using namespace llvm;

/***/

/* Move the constraint solving routing to ExecutionState, so that we can use the methods
   in S2EExecutionState::m_derefSolver */

bool TimingSolver::evaluate(const ExecutionState& state, ref<Expr> expr, Solver::Validity &result) { 
    return state.evaluate(*this, expr, result); 
}

bool TimingSolver::mustBeTrue(const ExecutionState& state, ref<Expr> expr, bool &result) { 
    return state.mustBeTrue(*this, expr, result); 
}

bool TimingSolver::mustBeFalse(const ExecutionState& state, ref<Expr> expr, bool &result) { 
    return state.mustBeFalse(*this, expr, result); 
}

bool TimingSolver::mayBeTrue(const ExecutionState& state, ref<Expr> expr, bool &result) { 
    return state.mayBeTrue(*this, expr, result); 
}

bool TimingSolver::mayBeFalse(const ExecutionState& state, ref<Expr> expr, bool &result) { 
    return state.mayBeFalse(*this, expr, result); 
}

bool TimingSolver::getValue(const ExecutionState& state, ref<Expr> expr, ref<ConstantExpr> &result) { 
    return state.getValue(*this, expr, result); 
}

bool TimingSolver::getInitialValues(const ExecutionState& state, 
                          const std::vector<const Array*> &objects,
                          std::vector< std::vector<unsigned char> > &result) {
    return state.getInitialValues(*this, objects, result);
}

bool TimingSolver::oEvaluate(const ExecutionState& state, ref<Expr> expr,
                            Solver::Validity &result) 
{
#ifdef __MHHUANG_MEASURE_TIME__
  //assert(state.currentProcStat != state.allProcStat.end() && "Something Error!\n");
  state.pCurProcStat->numEvaluate++;
  clock_t start = clock();
#endif
  // Fast path, to avoid timer and OS overhead.
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
    result = CE->isTrue() ? Solver::True : Solver::False;
#ifdef __MHHUANG_MEASURE_TIME__
  state.pCurProcStat->tEvaluate += (clock()-start);
#endif
    return true;
  }

  sys::TimeValue now(0,0),user(0,0),delta(0,0),sys(0,0);
  sys::Process::GetTimeUsage(now,user,sys);

  if (simplifyExprs)
    expr = state.constraints.simplifyExpr(expr);

  bool success = solver->evaluate(Query(state.constraints, expr), result);

  sys::Process::GetTimeUsage(delta,user,sys);
  delta -= now;
  stats::solverTime += delta.usec();
  state.queryCost += delta.usec()/1000000.;

#ifdef __MHHUANG_MEASURE_TIME__
  state.pCurProcStat->tEvaluate += (clock()-start);
#endif

  return success;
}

bool TimingSolver::oMustBeTrue(const ExecutionState& state, ref<Expr> expr, 
                              bool &result) 
{
  if(state.constraints.readyToUse() == false) {
    assert(false);
  }

#ifdef __MHHUANG_MEASURE_TIME__
  //assert(state.currentProcStat != state.allProcStat.end() && "Something Error!\n");
  state.pCurProcStat->numMustBeTrue++;
  clock_t start = clock();
#endif
  // Fast path, to avoid timer and OS overhead.
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
    result = CE->isTrue() ? true : false;
#ifdef __MHHUANG_MEASURE_TIME__
    state.pCurProcStat->tMustBeTrue += (clock()-start);
#endif
    return true;
  }

  sys::TimeValue now(0,0),user(0,0),delta(0,0),sys(0,0);
  sys::Process::GetTimeUsage(now,user,sys);

  if (simplifyExprs)
    expr = state.constraints.simplifyExpr(expr);

  bool success = solver->mustBeTrue(Query(state.constraints, expr), result);

  sys::Process::GetTimeUsage(delta,user,sys);
  delta -= now;
  stats::solverTime += delta.usec();
  state.queryCost += delta.usec()/1000000.;

#ifdef __MHHUANG_MEASURE_TIME__
    state.pCurProcStat->tMustBeTrue += (clock()-start);
#endif

  return success;
}

bool TimingSolver::oMustBeFalse(const ExecutionState& state, ref<Expr> expr,
                               bool &result) 
{
  return oMustBeTrue(state, Expr::createIsZero(expr), result);
}

bool TimingSolver::oMayBeTrue(const ExecutionState& state, ref<Expr> expr, 
                             bool &result) 
{
  bool res;
  if (!oMustBeFalse(state, expr, res))
    return false;
  result = !res;
  return true;
}

bool TimingSolver::oMayBeFalse(const ExecutionState& state, ref<Expr> expr, 
                              bool &result) 
{
  bool res;
  if (!oMustBeTrue(state, expr, res))
    return false;
  result = !res;
  return true;
}

bool TimingSolver::oGetValue(const ExecutionState& state, ref<Expr> expr, 
                            ref<ConstantExpr> &result) 
{
  if(state.constraints.readyToUse() == false) {
    assert(false);
  }

#ifdef __MHHUANG_MEASURE_TIME__
  //assert(state.currentProcStat != state.allProcStat.end() && "Something Error!\n");
  state.pCurProcStat->numGetValue++;
  clock_t start = clock();
#endif
  // Fast path, to avoid timer and OS overhead.
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
    result = CE;
#ifdef __MHHUANG_MEASURE_TIME__
    state.pCurProcStat->tGetValue += (clock()-start);
#endif
    return true;
  }
  
  sys::TimeValue now(0,0),user(0,0),delta(0,0),sys(0,0);
  sys::Process::GetTimeUsage(now,user,sys);

  if (simplifyExprs)
    expr = state.constraints.simplifyExpr(expr);

  bool success = solver->getValue(Query(state.constraints, expr), result);

  sys::Process::GetTimeUsage(delta,user,sys);
  delta -= now;
  stats::solverTime += delta.usec();
  state.queryCost += delta.usec()/1000000.;

#ifdef __MHHUANG_MEASURE_TIME__
    state.pCurProcStat->tGetValue += (clock()-start);
#endif

  return success;
}

bool TimingSolver::oGetInitialValues(const ExecutionState& state, 
                               const std::vector<const Array*> &objects,
                               std::vector< std::vector<unsigned char> > &result) 
{
  if(state.constraints.readyToUse() == false) {
    assert(false);
  }

  if (objects.empty())
    return true;

  sys::TimeValue now(0,0),user(0,0),delta(0,0),sys(0,0);
  sys::Process::GetTimeUsage(now,user,sys);

  bool success = solver->getInitialValues(Query(state.constraints,
                                                ConstantExpr::alloc(0, Expr::Bool)), 
                                          objects, result);
  
  sys::Process::GetTimeUsage(delta,user,sys);
  delta -= now;
  stats::solverTime += delta.usec();
  state.queryCost += delta.usec()/1000000.;
  
  return success;
}

std::pair< ref<Expr>, ref<Expr> >
TimingSolver::getRange(const ExecutionState& state, ref<Expr> expr) {
  return solver->getRange(Query(state.constraints, expr));
}

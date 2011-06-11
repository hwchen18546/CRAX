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
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */
//extern "C" {              
//#include "config.h"       
//#include "qemu-common.h"  
//}                         

#include "Example.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>


#define S2E_RAM_OBJECT_BITS 7
#define S2E_RAM_OBJECT_SIZE (1 << S2E_RAM_OBJECT_BITS)
#define S2E_RAM_OBJECT_MASK (~(S2E_RAM_OBJECT_SIZE - 1))
//#include <s2e/S2EExecutor.h>      
#include <s2e/S2EExecutionState.h>
//using namespace klee;
namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Example, "Example S2E plugin", "",);

void Example::initialize()
{
   m_monitor = static_cast<FunctionMonitor*>(s2e()->getPlugin("FunctionMonitor"));

/*
    m_traceBlockTranslation = s2e()->getConfig()->getBool(
                        getConfigKey() + ".traceBlockTranslation");
    m_traceBlockExecution = s2e()->getConfig()->getBool(
                        getConfigKey() + ".traceBlockExecution");
*/
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &Example::slotTranslateBlockStart));


    s2e()->getCorePlugin()->onDataMemoryAccess.connect(                                 
        sigc::mem_fun(*this, &Example::onDataMemoryAccess));

}

void Example::slotTranslateBlockStart(ExecutionSignal *signal, 
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc)
{
  //FunctionMonitor::CallSignal *callSignal;
  uint64_t functionAddress = 0x80484f5;

  if(callSignal)
  {
     return;
  }
  s2e()->getMessagesStream() << "IIIIIIIIIIIIIIMMMMMMMMMMMMMM" << std::endl;
  callSignal = m_monitor->getCallSignal(state, (uint64_t)0, (uint64_t)-1);
  callSignal->connect(sigc::mem_fun(*this, &Example::myFunctionCallMonitor));

/*
    if(m_traceBlockTranslation)
        std::cout << "Translating block at " << std::hex << pc << std::dec << std::endl;
    if(m_traceBlockExecution)
        signal->connect(sigc::mem_fun(*this, &Example::slotExecuteBlockStart));
*/
}

void Example::myFunctionCallMonitor(S2EExecutionState* state, FunctionMonitorState *fns)
{
  //s2e()->getMessagesStream() << "IIIIIIIIIIIIIIMMMMMMMMMMMMMM" << std::endl;
  uint64_t sp_value;
  state->readMemoryConcrete(state->getSp(), &sp_value, 4);
  //if(state->getPc() == 0x80483a4)
  //if(sp_value==0x0804857a)
//int64_t hostAddress =  state->getHostAddress((uint64_t)state->eip);
  //if(hostAddress ==  (uint64_t) -1)
    //return;
  //klee::ObjectPair op = state->addressSpace.findObject(hostAddress & S2E_RAM_OBJECT_MASK);

//if(state->getPc() >= 0x8048549  && state->getPc() <= 0x804859b)
//  ok = true;
//if(!op.second->isByteConcrete(hostAddress & ~S2E_RAM_OBJECT_MASK))
  //if(sp_value == 0x804857a)
  //if(ok)
  {
   //s2e()->getMessagesStream() << state->readCpuRegister(S2EExecutionState::CPU_OFFSET(eip), 8*sizeof(target_ulong));
  //s2e()->getMessagesStream() << "My function handler is called" << std::endl;
  //state->readMemoryConcrete(state->getBp(), &ret, 4);
//ret = 0xbfecd328;
 //s2e()->getWarningsStream() << "whatr??? "<< state->getBp() << " over!!!" << std::endl;
//s2e()->getWarningsStream() << "my pc = " << state->getEax() << std::endl;
//state->addConstraint( klee::EqExpr::create(state->getEax(), klee::ConstantExpr::alloc(0x123,klee::Expr::Int32)));
//state->addConstraint(klee::EqExpr::create(state->getEax(), klee::ConstantExpr::alloc(0x123,klee::Expr::Int32)));
    //state->addConstraint( klee::EqExpr::create(state->readMemory8(0xbfd21b20), klee::ConstantExpr::alloc(0xff,klee::Expr::Int8)));
     //s2e()->getWarningsStream() << state->readMemory8((uint64_t) 0xbffec700) << std::endl;
//s2e()->getWarningsStream() << "kind: " << klee::EqExpr::create(state->getEax(), klee::ConstantExpr::alloc(0x123,klee::Expr::Int32))->getKind() << std::endl;

//s2e()->getWarningsStream() << "pc = " << state->getPc() << std::endl;
 state->dumpX86State(s2e()->getWarningsStream());  
//state->dumpStack(20, state->getSp());
  FUNCMON_REGISTER_RETURN(state, fns, Example::myFunctionRetMontor);
  }
}

void Example::myFunctionRetMontor(S2EExecutionState *state)
{

 state->dumpX86State(s2e()->getWarningsStream());  
  //   state->dumpStack(40,state->getSp());
  //uint64_t bp_value;
  //state->readMemoryConcrete(state->getBp(), &bp_value, 4);
//s2e()->getWarningsStream() << "whatr??? "<< state->getBp() << " over!!!" << std::endl;


  //uint64_t bp_value = state->getBp();
  //state->readMemoryConcrete(state->getBp(), &bp_value, 4);
  //int dis = bp_value - address;

  int64_t hostAddress4 =  state->getHostAddress(state->getSp());
  if(hostAddress4 ==  (uint64_t) -1)
    return;
  klee::ObjectPair op4 = state->addressSpace.findObject(hostAddress4 & S2E_RAM_OBJECT_MASK);
  int64_t hostAddress5 =  state->getHostAddress(state->getSp()+1);
  if(hostAddress5 ==  (uint64_t) -1)
    return;
  klee::ObjectPair op5 = state->addressSpace.findObject(hostAddress5 & S2E_RAM_OBJECT_MASK);
  int64_t hostAddress6 =  state->getHostAddress(state->getSp()+2);
  if(hostAddress6 ==  (uint64_t) -1)
    return;
  klee::ObjectPair op6 = state->addressSpace.findObject(hostAddress6 & S2E_RAM_OBJECT_MASK);
  int64_t hostAddress7 =  state->getHostAddress(state->getSp()+3);
  if(hostAddress7 ==  (uint64_t) -1)
    return;
  klee::ObjectPair op7 = state->addressSpace.findObject(hostAddress7 & S2E_RAM_OBJECT_MASK);
   //uint64_t temp;
  if(0)
  //if(!op4.second->isByteConcrete(hostAddress4 & ~S2E_RAM_OBJECT_MASK) &&
  //   !op5.second->isByteConcrete(hostAddress5 & ~S2E_RAM_OBJECT_MASK) &&
  //   !op6.second->isByteConcrete(hostAddress6 & ~S2E_RAM_OBJECT_MASK) &&
  //   !op7.second->isByteConcrete(hostAddress7 & ~S2E_RAM_OBJECT_MASK))
  {
 // uint32_t bp_value ;//= state->getBp();
   //s2e()->getWarningsStream() << "reaMMMMMM << " << state->readMemory(ret+4,klee::Expr::Int8) << std::endl;
  //int dis = bp_value - address;
   //  state->dumpStack(20,ret);
    //s2e()->getMessagesStream() << "My ret handler is called" << std::endl;
    s2e()->getWarningsStream() << "OHOH~~~~ BUFFER OVERFLOW1111111 " << ret << std::endl;
  //printf("GOGOGO %x\n",state->getPc()); 
//  printf("%x\n",state->getBp());
    state->addConstraint( klee::EqExpr::create(state->readMemory8(state->getSp()), klee::ConstantExpr::alloc(0x8048424 & 0x000000ff,klee::Expr::Int8)));

//uint64_t bp_value;                                       
//state->readMemoryConcrete(ret+4, &bp_value, 4); 
//s2e()->getWarningsStream() << "whatr??? "<< state->readMemory8(ret + 4) << " over!!!" <<std::endl;
    state->addConstraint( klee::EqExpr::create(state->readMemory8(state->getSp()+1), klee::ConstantExpr::alloc((0x8048424 & 0x0000ff00) >> 8,klee::Expr::Int8)));
    state->addConstraint( klee::EqExpr::create(state->readMemory8(state->getSp()+2), klee::ConstantExpr::alloc((0x8048424 & 0x00ff0000) >> 16,klee::Expr::Int8)));
    state->addConstraint( klee::EqExpr::create(state->readMemory8(state->getSp()+3), klee::ConstantExpr::alloc((0x8048424 & 0xff000000) >> 24,klee::Expr::Int8)));
  }
}

void Example::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    std::cout << "Executing block at " << std::hex << pc << std::dec << std::endl;
}

void Example::onDataMemoryAccess(S2EExecutionState *state,            
                                       klee::ref<klee::Expr> virtualAddress,
                                       klee::ref<klee::Expr> hostAddress,   
                                       klee::ref<klee::Expr> value,         
                                       bool isWrite, bool isIO)             
{                                                          
  if(dyn_cast<klee::ConstantExpr>(virtualAddress)->getZExtValue() == (uint64_t)state->eip)                 
    s2e()->getWarningsStream() << virtualAddress << std::endl;
}


} // namespace plugins
} // namespace s2e
